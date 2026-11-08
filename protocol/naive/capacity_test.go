package naive_test

import (
	"net/http"
	"os"
	"testing"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing/common/auth"
	"golang.org/x/net/http2"
)

// This is a lifecycle stress test, not the separate-machine throughput/RSS
// benchmark. The opt-in keeps ordinary unit tests inexpensive.
func TestNaiveTwoThousandStreams(t *testing.T) {
	if os.Getenv("ACP_NAIVE_CAPACITY") != "1" {
		t.Skip("set ACP_NAIVE_CAPACITY=1 for 200 transports / 2000 flows")
	}
	for _, protocol := range []string{"h2", "h3", "mixed"} {
		t.Run(protocol, func(t *testing.T) {
			n, address, cfg, _ := fixture(t)
			var unaffected []*paddedStream
			for transportID := 0; transportID < 200; transportID++ {
				if transportID%20 == 0 {
					t.Logf("opening transport %d", transportID)
				}
				var transport http.RoundTripper
				if protocol == "h2" || protocol == "mixed" && transportID%2 == 0 {
					h := &http2.Transport{TLSClientConfig: cfg}
					transport = h
					t.Cleanup(h.CloseIdleConnections)
				} else {
					h := &http3.Transport{TLSClientConfig: cfg}
					transport = h
					t.Cleanup(func() { _ = h.Close() })
				}
				client := &http.Client{Transport: transport}
				for streamID := 0; streamID < 10; streamID++ {
					user, password := "a", "one"
					if streamID%2 == 0 {
						user, password = "b", "two"
					}
					stream := openStream(t, client, address, user, password)
					stream.echo(t, "before update")
					if user == "b" {
						unaffected = append(unaffected, stream)
					}
				}
			}
			for i := 0; i < 100; i++ {
				if err := n.UpdateUsers([]auth.User{{Username: "a", Password: "one"}, {Username: "b", Password: "two"}}); err != nil {
					t.Fatal(err)
				}
			}
			if count := n.CloseUserSessions("a"); count != 1000 {
				t.Fatalf("revoked %d streams, want 1000", count)
			}
			if err := n.RuntimeError(); err != nil {
				t.Fatal(err)
			}
			for _, stream := range unaffected {
				stream.echo(t, "survived revocation")
			}
			if err := n.Close(); err != nil {
				t.Fatal(err)
			}
			if err := n.Close(); err != nil {
				t.Fatal("repeated close:", err)
			}
		})
	}
}
