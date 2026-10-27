package webserver

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/webcontent"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"golang.org/x/net/http2"
)

func startProfileHandler(t *testing.T, handler http.Handler) *Server {
	t.Helper()
	s := New(handler, log.NewNOPFactory().Logger())
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func writeProbe(t *testing.T, conn net.Conn, value string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, value); err != nil {
		t.Fatal(err)
	}
}

func readProfileResponse(t *testing.T, reader *bufio.Reader, method string) *http.Response {
	t.Helper()
	response, err := http.ReadResponse(reader, &http.Request{Method: method})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func readProfileBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestProfileKeepAliveAndPipelining(t *testing.T) {
	s := newProfileServer(t)
	conn := profileConnection(t, s, "http/1.1")
	reader := bufio.NewReader(conn)
	// A bodyless HEAD followed immediately by a GET catches accidental response
	// boundary consumption. The last permitted request must really close, not
	// merely advertise close while net/http still waits for another request.
	writeProbe(t, conn, "HEAD / HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\nGET / HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n")
	for i := 1; i <= 100; i++ {
		method, body := "GET", referenceContent
		if i == 1 {
			method, body = "HEAD", ""
		} else if i > 2 {
			writeProbe(t, conn, "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n")
		}
		response := readProfileResponse(t, reader, method)
		if got := readProfileBody(t, response); got != body || response.StatusCode != 200 {
			t.Fatalf("request %d: status=%d body=%q", i, response.StatusCode, got)
		}
		if i < 100 {
			if response.Close || response.Header.Get("Keep-Alive") != fmt.Sprintf("timeout=5, max=%d", 101-i) {
				t.Fatalf("request %d: incorrect keep-alive %v", i, response.Header)
			}
		} else if !response.Close {
			t.Fatal("connection limit not enforced")
		}
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatal("connection not closed at request limit", err)
	}
}

func TestProfileProxyStreamingTrailersAndUpgrade(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "upstream")
		if r.URL.Path == "/upgrade" {
			conn, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Error(err)
				return
			}
			if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\nServer: upstream\r\n\r\n"); err != nil {
				t.Error(err)
				return
			}
			if err := rw.Flush(); err != nil {
				t.Error(err)
				return
			}
			data := make([]byte, 4096)
			if _, err := io.ReadFull(rw, data); err != nil {
				t.Error(err)
				return
			}
			if _, err := conn.Write(data); err != nil {
				t.Error(err)
			}
			return
		}
		w.Header().Set("Link", "</style.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Trailer", "X-Completed")
		if _, err := io.WriteString(w, "data: first\n\n"); err != nil {
			return // Client cancellation is expected during failed-test cleanup.
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return // A disconnected client cannot receive a flush.
		}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		if _, err := io.WriteString(w, "data: last\n\n"); err != nil {
			return // Client cancellation is expected during failed-test cleanup.
		}
		w.Header().Set("X-Completed", "yes")
	}))
	defer upstream.Close()
	defer finish()
	site, err := webcontent.New(option.WebOptions{Type: "proxy", URL: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	s := startProfileHandler(t, site)
	conn := profileConnection(t, s, "http/1.1")
	reader := bufio.NewReader(conn)
	writeProbe(t, conn, "GET /stream HTTP/1.1\r\nHost: example.test\r\n\r\n")
	interim := readProfileResponse(t, reader, "GET")
	defer interim.Body.Close()
	if interim.StatusCode != 103 || interim.Header.Get("Server") != "Apache" || interim.Header.Get("Link") == "" {
		t.Fatal("early hints corrupted", interim)
	}
	response := readProfileResponse(t, reader, "GET")
	defer response.Body.Close()
	first := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "data: first\n\n" {
		t.Fatal("stream buffered or corrupted before upstream completed", string(first), err)
	}
	finish()
	if body := readProfileBody(t, response); body != "data: last\n\n" || response.Trailer.Get("X-Completed") != "yes" {
		t.Fatal("chunk or trailer corrupted", body, response.Trailer)
	}
	// Reuse the exact connection after chunk trailers, then switch it to an
	// opaque bidirectional stream. HTTP-looking payload must stay untouched.
	writeProbe(t, conn, "GET /upgrade HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	upgraded := readProfileResponse(t, reader, "GET")
	defer upgraded.Body.Close()
	if upgraded.StatusCode != 101 || upgraded.Header.Get("Server") != "Apache" || upgraded.Header.Get("Upgrade") != "echo" {
		t.Fatal("upgrade corrupted", upgraded)
	}
	payload := []byte(strings.Repeat("HTTP/1.1 500\r\n\r\n\x00", 256))[:4096]
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, echo); err != nil || !bytes.Equal(payload, echo) {
		t.Fatal("opaque upgrade payload corrupted", err)
	}
}

func TestProfileHTTP2InitialFramesAndFlowControl(t *testing.T) {
	s := startProfileHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err := io.Copy(w, r.Body); err != nil {
			t.Error(err)
		}
	}))
	if got, want := initialHTTP2Frames(t, profileConnection(t, s, "h2")), []string{"SETTINGS 3=100", "WINDOW_UPDATE stream=0 increment=2147418112"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("HTTP/2 initial profile: %v, want %v", got, want)
	}
	transport := &http2.Transport{}
	cc, err := transport.NewClientConn(profileConnection(t, s, "h2"))
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	// Multiple rounds substantially exceed the 65535-byte stream window. This
	// fails if advertised SETTINGS and the engine's actual flow control differ.
	for i := 0; i < 3; i++ {
		payload := bytes.Repeat([]byte{0, 13, 10, 255, byte(i)}, 100000)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, err := http.NewRequestWithContext(ctx, "POST", "https://example.test/", bytes.NewReader(payload))
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		response, err := cc.RoundTrip(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		body := readProfileBody(t, response)
		cancel()
		if response.StatusCode != 200 || !bytes.Equal([]byte(body), payload) {
			t.Fatal("HTTP/2 bidirectional data corrupted", response.StatusCode, len(body))
		}
	}
}

type profileBufferConn struct {
	net.Conn // Only Write is used by the serialization tests.
	output   bytes.Buffer
}

func (c *profileBufferConn) Write(p []byte) (int, error) { return c.output.Write(p) }

func TestProfileFragmentedWrites(t *testing.T) {
	// Headers/chunk sizes can cross arbitrary Write boundaries. In particular,
	// HTTP-looking body bytes must never be interpreted as a new response.
	for _, stride := range []int{1, 7, 4096} {
		t.Run(fmt.Sprint(stride), func(t *testing.T) {
			conn := &profileBufferConn{}
			profile := newHTTP1Profile(conn)
			profile.begin(&http.Request{Method: "GET"})
			payload := "HTTP/1.1 500\r\n\r\n\x00"
			wire := "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n" +
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Done\r\n\r\n" +
				fmt.Sprintf("%x\r\n%s\r\n0\r\nX-Done: yes\r\n\r\n", len(payload), payload)
			for len(wire) > 0 {
				n := min(len(wire), stride)
				if written, err := profile.Write([]byte(wire[:n])); err != nil || written != n {
					t.Fatal("fragment write", written, err)
				}
				wire = wire[n:]
			}
			if profile.phase != responseHeaders {
				t.Fatal("chunk trailer did not end the response")
			}
			reader := bufio.NewReader(&conn.output)
			interim := readProfileResponse(t, reader, "GET")
			defer interim.Body.Close()
			if interim.StatusCode != 103 {
				t.Fatal("lost interim response")
			}
			response := readProfileResponse(t, reader, "GET")
			if body := readProfileBody(t, response); body != payload || response.Trailer.Get("X-Done") != "yes" {
				t.Fatal("fragmented response corruption", body, response.Trailer)
			}
		})
	}
}

func TestProfileParserErrors(t *testing.T) {
	s := newProfileServer(t)
	for _, probe := range apacheProbeRequests() {
		switch probe.name {
		case "missing-host", "duplicate-host", "invalid-host", "invalid-header", "invalid-escape", "long-header", "many-headers", "transfer-encoding", "long-uri", "bad-expect":
		default:
			continue
		}
		t.Run(probe.name, func(t *testing.T) {
			wire := profileExchange(t, profileConnection(t, s, "http/1.1"), probe.request)
			response := readProfileResponse(t, bufio.NewReader(strings.NewReader(wire)), "GET")
			body := readProfileBody(t, response)
			want := 400
			switch probe.name {
			case "long-uri":
				want = 414
			case "bad-expect":
				want = 417
			}
			if response.StatusCode != want || response.Header.Get("Server") != "Apache" || !strings.HasPrefix(body, "<!DOCTYPE HTML PUBLIC") || !response.Close || response.ContentLength != int64(len(body)) {
				t.Fatal("parser error escaped response normalization", wire)
			}
			title := http.StatusText(want)
			if want == 414 {
				title = "Request-URI Too Long"
			}
			if !strings.HasPrefix(wire, fmt.Sprintf("HTTP/1.1 %d %s\r\nDate: ", want, title)) || strings.Contains(wire, "X-Content-Type-Options") {
				t.Fatal("Go error suffix or header escaped normalization", wire)
			}
		})
	}
}
