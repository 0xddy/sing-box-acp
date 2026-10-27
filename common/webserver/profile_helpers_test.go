package webserver

import (
	"crypto/tls"
	"fmt"
	"github.com/sagernet/sing-box/common/webcontent"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"golang.org/x/net/http2"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const referenceContent = "<html><body><h1>It works!</h1></body></html>\n"

func newProfileServer(t *testing.T) *Server {
	t.Helper()
	site, err := webcontent.New(option.WebOptions{Type: "static", Content: referenceContent})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = site.Close() }) // Static sites have no closeable resources.
	s := New(site, log.NewNOPFactory().Logger())
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

func profileConnection(t *testing.T, s *Server, alpn string) net.Conn {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() }) // Test connection may already be closed.
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{NegotiatedProtocol: alpn, Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, HandshakeComplete: true}
	if err := s.Serve(server, state, nil); err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client
}

func profileExchange(t *testing.T, conn net.Conn, request string) string {
	t.Helper()
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func apacheProbeRequests() []struct{ name, request string } {
	request := func(line, headers string) string {
		return line + "\r\nHost: example.test\r\nConnection: close\r\n" + headers + "\r\n"
	}
	return []struct{ name, request string }{
		{"get", request("GET / HTTP/1.1", "")},
		{"head", request("HEAD / HTTP/1.1", "")},
		{"small-gzip", request("GET / HTTP/1.1", "Accept-Encoding: gzip\r\n")},
		{"options", request("OPTIONS / HTTP/1.1", "")},
		{"options-star", request("OPTIONS * HTTP/1.1", "")},
		{"brew", request("BREW / HTTP/1.1", "")},
		{"trace", request("TRACE / HTTP/1.1", "")},
		{"post", request("POST / HTTP/1.1", "Content-Length: 0\r\n")},
		{"http10", "GET / HTTP/1.0\r\n\r\n"},
		{"missing-host", "GET / HTTP/1.1\r\nConnection: close\r\n\r\n"},
		{"duplicate-host", request("GET / HTTP/1.1", "Host: second.test\r\n")},
		{"invalid-host", "GET / HTTP/1.1\r\nHost: bad host\r\nConnection: close\r\n\r\n"},
		{"invalid-header", request("GET / HTTP/1.1", "Bad Header: value\r\n")},
		{"http12", request("GET / HTTP/1.2", "")},
		{"http20", request("GET / HTTP/2.0", "")},
		{"http30", request("GET / HTTP/3.0", "")},
		{"range", request("GET / HTTP/1.1", "Range: bytes=0-4\r\n")},
		{"invalid-range", request("GET / HTTP/1.1", "Range: bytes=broken\r\n")},
		{"unsatisfied-range", request("GET / HTTP/1.1", "Range: bytes=9999-\r\n")},
		{"long-header", request("GET / HTTP/1.1", "X-Probe: "+strings.Repeat("a", 8200)+"\r\n")},
		{"long-uri", request("GET /"+strings.Repeat("a", 8200)+" HTTP/1.1", "")},
		{"many-headers", request("GET / HTTP/1.1", strings.Repeat("X-Probe: a\r\n", 101))},
		{"transfer-encoding", request("GET / HTTP/1.1", "Transfer-Encoding: gzip\r\n")},
		{"bad-expect", request("GET / HTTP/1.1", "Expect: unsupported\r\n")},
		{"head-bad-expect", request("HEAD / HTTP/1.1", "Expect: unsupported\r\n")},
		{"escaped-expect", request("GET / HTTP/1.1", "Expect: <test>&\"'\r\n")},
		{"duplicate-expect", request("GET / HTTP/1.1", "Expect: first\r\nExpect: second\r\n")},
		{"mixed-expect", request("GET / HTTP/1.1", "Expect: 100-continue\r\nExpect: second\r\n")},
		{"invalid-escape", request("GET /%XX HTTP/1.1", "")},
	}
}

func initialHTTP2Frames(t *testing.T, conn net.Conn) []string {
	t.Helper()
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(conn, conn)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	var frames []string
	var ack, window bool
	for !ack || !window {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				ack = true
				continue
			}
			var values []string
			if err := f.ForeachSetting(func(s http2.Setting) error { values = append(values, fmt.Sprintf("%d=%d", s.ID, s.Val)); return nil }); err != nil {
				t.Fatal(err)
			}
			frames = append(frames, "SETTINGS "+strings.Join(values, ","))
			if err := framer.WriteSettingsAck(); err != nil {
				t.Fatal(err)
			}
		case *http2.WindowUpdateFrame:
			frames = append(frames, fmt.Sprintf("WINDOW_UPDATE stream=%d increment=%d", f.StreamID, f.Increment))
			window = f.StreamID == 0
		default:
			t.Fatalf("unexpected initial frame %T", frame)
		}
	}
	return frames
}
