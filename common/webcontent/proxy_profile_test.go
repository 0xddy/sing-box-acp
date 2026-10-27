package webcontent

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestProxyProfileInterimAndStreamingResponses(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "upstream")
		w.Header().Set("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Content-Type", "text/event-stream")
		if _, err := io.WriteString(w, "data: first\n\n"); err != nil {
			return // The test client has disconnected.
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return // A closed client connection cannot be flushed.
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	defer close(release)
	site, err := New(option.WebOptions{Type: "proxy", URL: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	front := httptest.NewServer(site)
	defer front.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	interim := make(chan textproto.MIMEHeader, 1)
	trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
		if code == 103 {
			interim <- textproto.MIMEHeader(http.Header(h).Clone())
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", front.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if got := response.Header.Values("Server"); len(got) != 1 || got[0] != "Apache" {
		t.Fatal("final response identity", got)
	}
	select {
	case h := <-interim:
		if got := h.Values("Server"); len(got) != 1 || got[0] != "Apache" || h.Get("Link") == "" {
			t.Fatal("interim response identity", h)
		}
	default:
		t.Fatal("early hints were lost")
	}
	line, err := bufio.NewReader(response.Body).ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatal("response was buffered instead of streaming", line, err)
	}
}

func TestProxyProfileProtocolUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\nServer: upstream\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err := rw.Flush(); err != nil {
			t.Error(err)
			return
		}
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		ping := make([]byte, 4)
		if _, err := io.ReadFull(rw, ping); err != nil {
			t.Error(err)
			return
		}
		if _, err := conn.Write(ping); err != nil {
			t.Error(err)
		}
	}))
	defer upstream.Close()
	site, err := New(option.WebOptions{Type: "proxy", URL: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	front := httptest.NewServer(site)
	defer front.Close()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(front.URL, "http://"), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 101 || response.Header.Get("Server") != "Apache" {
		t.Fatal("protocol upgrade failed", response)
	}
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	pong := make([]byte, 4)
	if _, err := io.ReadFull(reader, pong); err != nil || string(pong) != "ping" {
		t.Fatal("upgraded connection broken", err)
	}
}

func TestProxyProfileResponseTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer upstream.Close()
	site, err := New(option.WebOptions{Type: "proxy", URL: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	site.transport.ResponseHeaderTimeout = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	w := httptest.NewRecorder()
	site.ServeHTTP(w, httptest.NewRequestWithContext(ctx, "GET", "https://example.com/", nil))
	if w.Code != 504 || w.Header().Get("Server") != "Apache" || !strings.Contains(w.Body.String(), "<h1>Gateway Timeout</h1>") {
		t.Fatal("response timeout profile", w)
	}
}
