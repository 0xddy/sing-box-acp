package naive_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	h3qlog "github.com/sagernet/quic-go/http3/qlog"
	"github.com/sagernet/sing-box/option"
)

func TestApacheHTTP3Reference(t *testing.T) {
	address := os.Getenv("ACP_APACHE_HTTP3_REFERENCE_ADDR")
	if address == "" {
		t.Skip("set ACP_APACHE_HTTP3_REFERENCE_ADDR to the isolated Apache HTTP/3 reference")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("reference must use loopback")
	}
	_, actualAddress, actualTLS, router := fixtureWithWeb(t, &option.WebOptions{Type: "static", Content: "<h1>Website</h1>\n"})
	type result struct {
		Status                           int
		Server, ContentType, Allow, Body string
	}
	connect := func(address string, cfg *tls.Config) *http3.ClientConn {
		cfg = cfg.Clone()
		cfg.NextProtos = []string{http3.NextProtoH3}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// QLOGDIR enables per-peer transport parameters, HTTP/3 settings and
		// close events for the reference difference report.
		conn, err := quic.DialAddr(ctx, address, cfg, &quic.Config{Tracer: h3qlog.DefaultConnectionTracer})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
		client := (&http3.Transport{}).NewClientConn(conn)
		select {
		case <-client.ReceivedSettings():
		case <-ctx.Done():
			t.Fatal("missing HTTP/3 settings")
		}
		t.Logf("%s settings: %+v", address, client.Settings())
		return client
	}
	actual := connect(actualAddress, actualTLS)
	// Only the isolated, ephemeral reference certificate bypasses verification.
	reference := connect(address, &tls.Config{InsecureSkipVerify: true})
	for _, method := range []string{"GET", "HEAD", "POST", "OPTIONS", "CONNECT", "TRACE", "UNKNOWN"} {
		t.Run(method, func(t *testing.T) {
			request := func(client *http3.ClientConn, address string) result {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				req, _ := http.NewRequestWithContext(ctx, method, "https://"+address+"/", nil)
				req.Host = "example.com:443"
				req.Header.Set("Padding", "probe")
				req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("a:wrong")))
				response, err := client.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if response.Header.Get("Padding") != "" || response.Header.Get("Proxy-Authenticate") != "" {
					t.Fatal("website exposed proxy authentication")
				}
				allow := strings.Split(response.Header.Get("Allow"), ",")
				for i := range allow {
					allow[i] = strings.TrimSpace(allow[i])
				}
				sort.Strings(allow)
				return result{response.StatusCode, response.Header.Get("Server"), response.Header.Get("Content-Type"), strings.Join(allow, ","), string(body)}
			}
			got, want := request(actual, actualAddress), request(reference, address)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("HTTP/3 website mismatch:\nGo: %+v\nApache: %+v", got, want)
			}
		})
	}
	if router.routed.Load() != 0 {
		t.Fatal("reference website probes entered accounting")
	}
}
