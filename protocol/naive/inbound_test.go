package naive_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/naive"
	_ "github.com/sagernet/sing-box/protocol/naive/quic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/http2"
)

type echoRouter struct {
	adapter.Router
	routed atomic.Int32
	t      *testing.T
	handle func(net.Conn)
}

func (r *echoRouter) RouteConnectionEx(ctx context.Context, c net.Conn, m adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.routed.Add(1)
	if m.User == "" || m.InboundType != "naive" {
		r.t.Error("lost accounting identity")
	}
	go func() {
		defer func() {
			if v := recover(); v != nil {
				r.t.Errorf("echo panic: %v", v)
			}
		}()
		var err error
		if r.handle != nil {
			r.handle(c)
		} else {
			_, err = io.Copy(c, c)
		}
		_ = c.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

func fixture(t *testing.T) (*naive.Inbound, string, *tls.Config, *echoRouter) {
	return fixtureWithWeb(t, &option.WebOptions{Type: "static", Content: "<h1>Website</h1>"})
}

func fixtureWithWeb(t *testing.T, web *option.WebOptions) (*naive.Inbound, string, *tls.Config, *echoRouter) {
	t.Helper()
	options, clientTLS := fixtureOptions(t, web)
	router := &echoRouter{t: t}
	created, err := naive.NewInbound(context.Background(), router, log.NewNOPFactory().Logger(), "naive-test", options)
	if err != nil {
		t.Fatal(err)
	}
	n := created.(*naive.Inbound)
	scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { _ = scope.Close() })
	for _, stage := range adapter.ListStartStages {
		if err = n.Start(stage, scope); err != nil {
			t.Fatal(err)
		}
	}
	return n, fmt.Sprintf("127.0.0.1:%d", options.ListenPort), clientTLS, router
}

func fixtureOptions(t *testing.T, web *option.WebOptions) (option.NaiveInboundOptions, *tls.Config) {
	t.Helper()
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(probe.Addr().(*net.TCPAddr).Port)
	_ = probe.Close()
	options := option.NaiveInboundOptions{
		ListenOptions:              option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))), ListenPort: port},
		Users:                      []auth.User{{Username: "a", Password: "one"}, {Username: "b", Password: "two"}},
		Web:                        web,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{Enabled: true, Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))}, Key: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))}}},
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	return options, &tls.Config{RootCAs: roots, ServerName: "example.com"}
}

type paddedStream struct {
	write          io.WriteCloser
	read           io.ReadCloser
	sent, received int
}

func (s *paddedStream) echo(t *testing.T, message string) {
	t.Helper()
	payload := []byte(message)
	if s.sent < 8 {
		framed := make([]byte, 3+len(payload))
		binary.BigEndian.PutUint16(framed, uint16(len(payload)))
		copy(framed[3:], payload)
		payload = framed
	}
	s.sent++
	if _, err := s.write.Write(payload); err != nil {
		t.Fatal(err)
	}
	var got []byte
	if s.received < 8 {
		header := make([]byte, 3)
		if _, err := io.ReadFull(s.read, header); err != nil {
			t.Fatal(err)
		}
		got = make([]byte, int(binary.BigEndian.Uint16(header))+int(header[2]))
		if _, err := io.ReadFull(s.read, got); err != nil {
			t.Fatal(err)
		}
		got = got[:binary.BigEndian.Uint16(header)]
	} else {
		got = make([]byte, len(message))
		if _, err := io.ReadFull(s.read, got); err != nil {
			t.Fatal(err)
		}
	}
	s.received++
	if string(got) != message {
		t.Fatalf("echo mismatch: %q", got)
	}
}
func (s *paddedStream) close() { _ = s.write.Close(); _ = s.read.Close() }

func openStream(t *testing.T, client *http.Client, address, user, password string) *paddedStream {
	t.Helper()
	reader, writer := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	request, _ := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+address, reader)
	request.Host = "example.com:443"
	request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)))
	request.Header.Set("Padding", "test")
	response, err := client.Do(request)
	if err != nil {
		_ = writer.Close()
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		_ = response.Body.Close()
		_ = writer.Close()
		t.Fatalf("CONNECT status %d", response.StatusCode)
	}
	s := &paddedStream{write: writer, read: response.Body}
	t.Cleanup(s.close)
	return s
}

func TestWebAuthenticationAndPerStreamRevocation(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			n, address, tlsConfig, router := fixture(t)
			var transport http.RoundTripper
			if protocol == "h2" {
				h := &http2.Transport{TLSClientConfig: tlsConfig}
				transport = h
				t.Cleanup(h.CloseIdleConnections)
			} else {
				h := &http3.Transport{TLSClientConfig: tlsConfig}
				transport = h
				t.Cleanup(func() { _ = h.Close() })
			}
			client := &http.Client{Transport: transport}
			response, err := client.Get("https://" + address + "/")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || string(body) != "<h1>Website</h1>" || response.Header.Get("Server") != "Apache" {
				t.Fatal("website", err)
			}
			if router.routed.Load() != 0 {
				t.Fatal("website entered accounting")
			}
			a := openStream(t, client, address, "a", "one")
			b := openStream(t, client, address, "b", "two")
			a.echo(t, "first")
			b.echo(t, "second")
			if got := n.CloseUserSessions("a"); got != 1 {
				t.Fatalf("revoke count %d", got)
			}
			b.echo(t, "still alive")
			if err = n.UpdateUsers(nil); err != nil {
				t.Fatal(err)
			}
			request, _ := http.NewRequest(http.MethodConnect, "https://"+address, nil)
			request.Host = "example.com:443"
			request.Header.Set("Padding", "test")
			request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("a:one")))
			response, err = client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode == 200 || response.StatusCode == 407 || response.Header.Get("Padding") != "" {
				t.Fatal("empty users exposed proxy")
			}
		})
	}
}

func TestHTTP1ConnectLeavesWebsiteFraming(t *testing.T) {
	_, address, cfg, _ := fixture(t)
	cfg.NextProtos = []string{"http/1.1"}
	c, err := tls.Dial("tcp", address, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nPadding: test\r\nProxy-Authorization: Basic %s\r\n\r\n", base64.StdEncoding.EncodeToString([]byte("a:one")))
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(c)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != 200 {
		t.Fatal("CONNECT", err)
	}
	s := &paddedStream{write: c, read: io.NopCloser(reader)}
	for i := 0; i < 12; i++ {
		s.echo(t, strings.Repeat("opaque HTTP/1.1\r\n", 20))
	}
}

func TestLongLivedStreamAndUploadHalfClose(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			t.Parallel()
			_, address, cfg, router := fixture(t)
			router.handle = func(c net.Conn) {
				body, err := io.ReadAll(c)
				if err != nil {
					t.Errorf("target read: %v", err)
					return
				}
				// The target waits for upload EOF before producing its response.
				if _, err = c.Write(append([]byte("response:"), body...)); err != nil {
					t.Errorf("target write: %v", err)
				}
			}
			var transport http.RoundTripper
			if protocol == "h2" {
				h := &http2.Transport{TLSClientConfig: cfg}
				transport = h
				t.Cleanup(h.CloseIdleConnections)
			} else {
				h := &http3.Transport{TLSClientConfig: cfg}
				transport = h
				t.Cleanup(func() { _ = h.Close() })
			}
			stream := openStream(t, &http.Client{Transport: transport}, address, "a", "one")
			// Cross the website's 30-second absolute I/O limit without traffic.
			delay := 31 * time.Second
			if testing.Short() {
				delay = 0
			}
			timer := time.NewTimer(delay)
			defer timer.Stop()
			<-timer.C
			_, err := stream.write.Write([]byte{0, 4, 0, 'b', 'o', 'd', 'y'})
			if err != nil {
				t.Fatal(err)
			}
			if err = stream.write.Close(); err != nil {
				t.Fatal(err)
			}
			header := make([]byte, 3)
			if _, err = io.ReadFull(stream.read, header); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, int(binary.BigEndian.Uint16(header))+int(header[2]))
			if _, err = io.ReadFull(stream.read, data); err != nil {
				t.Fatal(err)
			}
			if string(data[:binary.BigEndian.Uint16(header)]) != "response:body" {
				t.Fatal("truncated half-close response")
			}
			if _, err = io.ReadAll(stream.read); err != nil {
				t.Fatalf("response did not end cleanly: %v", err)
			}
		})
	}
}
