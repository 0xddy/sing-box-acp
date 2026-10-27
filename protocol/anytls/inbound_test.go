package anytls

import (
	"bufio"
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	client "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/http2"
)

type echoRouter struct {
	t *testing.T
	adapter.Router
	routed atomic.Int32
	users  chan string
}

func (r *echoRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.routed.Add(1)
	r.users <- metadata.User
	go func() {
		defer conn.Close()
		defer func() {
			if value := recover(); value != nil {
				r.t.Errorf("echo stream panic: %v", value)
			}
		}()
		_, err := io.Copy(conn, conn)
		if onClose != nil {
			onClose(err)
		}
	}()
}

type fragmentedWriter struct {
	net.Conn
	remaining int
}

func (c *fragmentedWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		size := len(p)
		if c.remaining > 0 {
			size = 1
			c.remaining--
		}
		n, err := c.Conn.Write(p[:size])
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func TestTLSAuthenticationWebFallbackAndRevocation(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := fixture.TLS.Certificates[0]
	fixture.Close()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	router := &echoRouter{t: t, users: make(chan string, 16)}
	server, err := NewInbound(context.Background(), router, log.NewNOPFactory().Logger(), "anytls", option.AnyTLSInboundOptions{
		ListenOptions:              option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1")))},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{Enabled: true, ALPN: []string{"h2", "http/1.1"}, Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}))}, Key: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))}}},
		Users:                      []option.AnyTLSUser{{Name: "user-1", Password: "first"}, {Name: "user-2", Password: "second"}}, Web: &option.WebOptions{Type: "static", Content: "<h1>Website</h1>"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := server.(*Inbound)
	defer h.Close()
	if err = h.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	address := h.listener.TCPListener().Addr().String()
	dial := func(alpn string) (net.Conn, error) {
		cfg := &stdtls.Config{InsecureSkipVerify: true}
		if alpn != "" {
			cfg.NextProtos = []string{alpn}
		}
		return stdtls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, cfg)
	}
	for _, alpn := range []string{"", "http/1.1", "h2"} {
		t.Run("proxy-"+alpn, func(t *testing.T) {
			c, err := client.NewClient(context.Background(), client.ClientConfig{Password: "first", Logger: log.NewNOPFactory().Logger(), DialOut: func(context.Context) (net.Conn, error) {
				conn, err := dial(alpn)
				if err != nil {
					return nil, err
				}
				return &fragmentedWriter{Conn: conn, remaining: 40}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			conn, err := c.CreateProxy(context.Background(), M.ParseSocksaddr("example.com:80"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err = conn.Write([]byte("echo")); err != nil {
				t.Fatal(err)
			}
			body := make([]byte, 4)
			if _, err = io.ReadFull(conn, body); err != nil || string(body) != "echo" {
				t.Fatal("proxy", err)
			}
			if user := <-router.users; user != "user-1" {
				t.Fatal("accounting identity", user)
			}
			if count := h.CloseUserSessions("user-1"); count < 1 {
				t.Fatal("no transport revoked")
			}
			if _, err = conn.Read(body); err == nil {
				t.Fatal("revoked stream survived")
			}
		})
	}
	routed := router.routed.Load()
	for _, tc := range []struct {
		name, alpn, request string
		status              int
	}{
		{"short-http-without-alpn", "", "GET / HTTP/1.0\r\n\r\n", 200},
		{"extension-method", "http/1.1", "BREW / HTTP/1.0\r\n\r\n", 501},
		{"trace-disabled", "http/1.1", "TRACE / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", 405},
		{"options-star", "http/1.1", "OPTIONS * HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", 200},
		{"text-http20", "http/1.1", "GET / HTTP/2.0\r\nHost: example.com\r\nConnection: close\r\n\r\n", 200},
		{"text-http30", "http/1.1", "GET / HTTP/3.0\r\nHost: example.com\r\nConnection: close\r\n\r\n", 200},
		{"expectation-failed", "http/1.1", "GET / HTTP/1.1\r\nHost: example.com\r\nExpect: unsupported\r\nConnection: close\r\n\r\n", 417},
		{"unsatisfied-range", "http/1.1", "GET / HTTP/1.1\r\nHost: example.com\r\nRange: bytes=1000-\r\nConnection: close\r\n\r\n", 416},
		{"http2-preface", "h2", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := dial(tc.alpn)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			var response *http.Response
			if tc.alpn == "h2" {
				transport := &http2.Transport{}
				cc, err := transport.NewClientConn(conn)
				if err != nil {
					t.Fatal(err)
				}
				request, _ := http.NewRequest("GET", "https://example.com/", nil)
				response, err = cc.RoundTrip(request)
				if err != nil {
					t.Fatal(err)
				}
				for _, probe := range []struct {
					method string
					status int
				}{{"HEAD", 200}, {"OPTIONS", 200}, {"POST", 200}, {"TRACE", 405}, {"BREW", 501}} {
					request, err := http.NewRequest(probe.method, "https://example.com/", nil)
					if err != nil {
						t.Fatal(err)
					}
					result, err := cc.RoundTrip(request)
					if err != nil {
						t.Fatal(err)
					}
					func() {
						defer result.Body.Close()
						body, err := io.ReadAll(result.Body)
						if err != nil || result.StatusCode != probe.status || result.Header.Get("Server") != "Apache" {
							t.Fatalf("HTTP/2 %s profile: status=%d headers=%v error=%v", probe.method, result.StatusCode, result.Header, err)
						}
						if (probe.method == "HEAD" || probe.method == "OPTIONS") && len(body) != 0 {
							t.Fatalf("HTTP/2 %s contains a body", probe.method)
						}
					}()
				}
			} else {
				// A complete HTTP/1.0 request shorter than the AnyTLS auth digest.
				for _, b := range []byte(tc.request) {
					if _, err = conn.Write([]byte{b}); err != nil {
						t.Fatal(err)
					}
				}
				response, err = http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status {
				t.Fatal(response.StatusCode)
			}
			if response.Header.Get("Server") != "Apache" {
				t.Fatal("website server profile missing", response.Header)
			}
			if tc.name == "options-star" {
				if len(body) != 0 || response.Header.Get("Allow") != "" {
					t.Fatal("OPTIONS * bypassed website profile", response.Header)
				}
			} else if tc.status == http.StatusOK && string(body) != "<h1>Website</h1>" {
				t.Fatalf("HTML response changed: %q", body)
			}
		})
	}
	if router.routed.Load() != routed {
		t.Fatal("web traffic entered proxy accounting")
	}
	if err = h.UpdateUsers([]option.AnyTLSUser{{Name: "user-2", Password: "second"}}); err != nil {
		t.Fatal(err)
	}
}
