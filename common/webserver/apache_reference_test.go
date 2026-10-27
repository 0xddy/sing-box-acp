package webserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestApacheReference(t *testing.T) {
	address := os.Getenv("ACP_APACHE_REFERENCE_ADDR")
	if address == "" {
		t.Skip("set ACP_APACHE_REFERENCE_ADDR to the loopback TLS port of testdata/apache")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("the Apache reference must be an isolated loopback listener")
	}
	s := newProfileServer(t)
	for _, probe := range apacheProbeRequests() {
		t.Run(probe.name, func(t *testing.T) {
			conn := dialApacheReference(t, address, "http/1.1")
			actual := profileExchange(t, profileConnection(t, s, "http/1.1"), probe.request)
			reference := profileExchange(t, conn, probe.request)
			got := normalizeReferenceResponse(t, actual)
			want := normalizeReferenceResponse(t, reference)
			if got != want {
				t.Fatalf("response differs (see normalization contract):\nGo: %q\nApache: %q", got, want)
			}
		})
	}
	t.Run("h2-initial-frames", func(t *testing.T) {
		actual := initialHTTP2Frames(t, profileConnection(t, s, "h2"))
		reference := initialHTTP2Frames(t, dialApacheReference(t, address, "h2"))
		if !reflect.DeepEqual(actual, reference) {
			t.Fatalf("Go=%v Apache=%v", actual, reference)
		}
		t.Log(actual)
	})
	for _, protocol := range []string{"http/1.1", "h2"} {
		for _, probe := range []struct{ name, method, header, value string }{
			{"range", "GET", "Range", "bytes=9999-"},
			{"head-range", "HEAD", "Range", "bytes=9999-"},
			{"expect", "GET", "Expect", "<test>&\"'"},
			{"head-expect", "HEAD", "Expect", "unsupported"},
		} {
			t.Run(protocol+"-"+probe.name, func(t *testing.T) {
				type result struct {
					status                          int
					length                          int64
					encoding                        []string
					contentType, contentRange, body string
				}
				request := func(conn net.Conn) result {
					defer conn.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					req, err := http.NewRequestWithContext(ctx, probe.method, "https://example.test/", nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set(probe.header, probe.value)
					var response *http.Response
					if protocol == "h2" {
						transport := &http2.Transport{DisableCompression: true}
						cc, err := transport.NewClientConn(conn)
						if err != nil {
							t.Fatal(err)
						}
						defer cc.Close()
						response, err = cc.RoundTrip(req)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						writeProbe(t, conn, fmt.Sprintf("%s / HTTP/1.1\r\nHost: example.test\r\n%s: %s\r\n\r\n", probe.method, probe.header, probe.value))
						response = readProfileResponse(t, bufio.NewReader(conn), probe.method)
					}
					return result{response.StatusCode, response.ContentLength, response.TransferEncoding, response.Header.Get("Content-Type"), response.Header.Get("Content-Range"), readProfileBody(t, response)}
				}
				got := request(profileConnection(t, s, protocol))
				want := request(dialApacheReference(t, address, protocol))
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("persistent %s error response differs:\nGo=%+v\nApache=%+v", protocol, got, want)
				}
			})
		}
	}
}

func dialApacheReference(t *testing.T, address, alpn string) net.Conn {
	t.Helper()
	// Both peers use the default vhost with no SNI. Apache rejects HTTP/1.0
	// without Host when SNI is present, which is a separate vhost policy.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{alpn}})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// Comparison contract: retain status line, header order/casing and body. Only
// replace valid dates/mtime; compare Allow as a set (APR hash iteration varies
// across restarts). The reference advertises Upgrade: h2 even with H2Upgrade off;
// this Go listener negotiates h2 via ALPN only. Assert close on both then omit
// those two transport headers. All other headers and body bytes must match.
func normalizeReferenceResponse(t *testing.T, wire string) string {
	t.Helper()
	head, body, ok := strings.Cut(wire, "\r\n\r\n")
	if !ok {
		t.Fatal("incomplete response", wire)
	}
	var lines []string
	var closing bool
	for _, line := range strings.Split(head, "\r\n") {
		name, value, ok := strings.Cut(line, ": ")
		if ok {
			switch name {
			case "Date", "Last-Modified":
				if _, err := http.ParseTime(value); err != nil {
					t.Fatal(err)
				}
				line = name + ": <date>"
			case "ETag":
				if !regexp.MustCompile(`^"2d-[0-9a-f]+"$`).MatchString(value) {
					t.Fatal("unexpected reference ETag", value)
				}
				line = name + ": <size-mtime>"
			case "Allow":
				methods := strings.Split(value, ",")
				slices.Sort(methods)
				line = name + ": " + strings.Join(methods, ",")
			case "Upgrade":
				if value != "h2" {
					t.Fatal("unexpected protocol advertisement", line)
				}
				continue
			case "Connection":
				closing = value == "close" || value == "Upgrade, close"
				continue
			}
		}
		lines = append(lines, line)
	}
	if !closing {
		t.Fatal("reference probe must close its connection", head)
	}
	return strings.Join(lines, "\r\n") + "\r\n\r\n" + body
}
