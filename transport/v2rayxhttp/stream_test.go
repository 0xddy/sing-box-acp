package v2rayxhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type handlerFunc func(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc)

func (f handlerFunc) NewConnectionEx(ctx context.Context, c net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	f(ctx, c, source, destination, onClose)
}

type h2Config struct{ aTLS.Config }

func (h2Config) NextProtos() []string { return []string{"h2"} }

func TestStreamOptions(t *testing.T) {
	for _, tc := range []struct{ path, mode, want string }{
		{"", "", "/"}, {"proxy", "stream-one", "/proxy/"}, {"/proxy/", "", "/proxy/"},
		{"/proxy", "packet-up", "/proxy/"}, {"/proxy", "stream-up", "/proxy/"}, {"/proxy?token=abc", "auto", "/proxy/"}, {"/proxy", "invalid", ""},
	} {
		o, err := normalizeOptions(Options{Path: tc.path, Mode: tc.mode}, h2Config{})
		got := ""
		if err == nil {
			got = newCodec(o).basePath
		}
		if got != tc.want || (err != nil) != (tc.want == "") {
			t.Fatalf("%q, %q: %q, %v", tc.path, tc.mode, got, err)
		}
	}
	if _, err := normalizeOptions(Options{}, nil); err == nil {
		t.Fatal("accepted plaintext XHTTP")
	}
	s := testServer(t, Options{Host: "proxy.test", Path: "/x/", Mode: ModeStreamOne}, nil)
	for _, tc := range []struct {
		host, path, method, pad string
		status                  int
	}{
		{"other.test", "/x/", "POST", strings.Repeat("X", 120), 404}, {"proxy.test", "/x/session/", "POST", strings.Repeat("X", 120), 404},
		{"proxy.test", "/x/", "GET", strings.Repeat("X", 120), 404}, {"proxy.test", "/x/", "POST", "", 400},
	} {
		req := httptest.NewRequest(tc.method, "https://"+tc.host+tc.path, nil)
		req.ProtoMajor = 2
		req.Header.Set("Referer", "https://"+tc.host+"/x/?x_padding="+tc.pad)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("%+v: HTTP %d", tc, w.Code)
		}
	}
}

func TestStreamDeadlineAndClose(t *testing.T) {
	var calls int
	c, input, output := newStream(nil, nil, func() { calls++ })
	defer input.Close()
	defer output.Close()
	defer c.Close()
	c.SetDeadline(time.Now().Add(-time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline", err)
	}
	if _, err := c.Write([]byte{1}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("write deadline", err)
	}
	c.SetDeadline(time.Time{})
	go c.receive(input, bytes.NewBufferString("tail"))
	c.CloseWrite()
	if body, err := io.ReadAll(output); err != nil || len(body) != 0 {
		t.Fatal("write half-close", body, err)
	}
	if body, err := io.ReadAll(c); err != nil || string(body) != "tail" {
		t.Fatal("read after half-close", body, err)
	}
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() { defer wg.Done(); c.Close() }()
	}
	wg.Wait()
	if calls != 1 {
		t.Fatal("stream closed multiple times")
	}
}

func TestServerRetainsUploadAfterDownloadHalfClose(t *testing.T) {
	halfClosed := make(chan struct{})
	tail := make(chan string, 1)
	handler := handlerFunc(func(_ context.Context, c net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
		_, err := c.Write([]byte("reply"))
		if err == nil {
			err = c.(N.WriteCloser).CloseWrite()
		}
		close(halfClosed)
		b, readErr := io.ReadAll(c)
		if err == nil {
			err = readErr
		}
		tail <- string(b)
		onClose(err)
	})
	h := httptest.NewUnstartedServer(testServer(t, Options{Path: "/x/", Mode: ModeStreamOne}, handler))
	h.EnableHTTP2 = true
	h.StartTLS()
	defer h.Close()
	uploadReader, upload := io.Pipe()
	defer upload.Close()
	req, err := http.NewRequest("POST", h.URL+"/x/", uploadReader)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := url.Parse(h.URL + "/x/")
	ref.RawQuery = "x_padding=" + strings.Repeat("X", 120)
	req.Header.Set("Referer", ref.String())
	client := h.Client()
	client.Timeout = 3 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	select {
	case <-halfClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("missing server half-close")
	}
	if _, err := upload.Write([]byte("upload tail")); err != nil {
		t.Fatal(err)
	}
	upload.Close()
	reply, err := io.ReadAll(resp.Body)
	if err != nil || string(reply) != "reply" {
		t.Fatalf("reply %q, err %v", reply, err)
	}
	if got := <-tail; got != "upload tail" {
		t.Fatalf("received %q", got)
	}
}

func TestClientResetAndStreamIsolation(t *testing.T) {
	handler := handlerFunc(func(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
		_, err := io.Copy(conn, conn)
		onClose(err)
	})
	server := httptest.NewUnstartedServer(testServer(t, Options{}, handler))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	config, err := tls.NewClient(ctx, logger.NOP(), "localhost", option.OutboundTLSOptions{Enabled: true, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ctx, N.SystemDialer, M.SocksaddrFromNet(server.Listener.Addr()), option.V2RayXHTTPOptions{}, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	dial := func() net.Conn {
		conn, err := client.DialContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		return conn
	}
	echo := func(conn net.Conn) {
		t.Helper()
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		var buf [4]byte
		if _, err := io.ReadFull(conn, buf[:]); err != nil || string(buf[:]) != "ping" {
			t.Fatalf("echo %q: %v", buf, err)
		}
	}
	one, two := dial(), dial()
	echo(one)
	one.Close()
	echo(two)
	client.Close()
	_, err = two.Read(make([]byte, 1))
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("pool reset did not interrupt the stream: %v", err)
	}
	two.Close()
	three := dial()
	defer three.Close()
	echo(three)
}

func testServer(t *testing.T, opts Options, handler handlerFunc) *Server {
	t.Helper()
	opts, err := normalizeOptions(opts, h2Config{})
	if err != nil {
		t.Fatal(err)
	}
	return &Server{opts: opts, codec: newCodec(opts), handler: handler}
}
