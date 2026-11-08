package naive_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/naive"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/http2"
)

type metadataRouter struct {
	adapter.Router
	metadata chan adapter.InboundContext
}

func (r *metadataRouter) RouteConnectionEx(_ context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.metadata <- metadata
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func TestNaiveRoutingMetadata(t *testing.T) {
	for _, protocol := range []string{"http1", "http2", "http3"} {
		for _, detour := range []string{"", "target-inbound"} {
			t.Run(protocol+"/detour="+detour, func(t *testing.T) {
				options, clientTLS := fixtureOptions(t, &option.WebOptions{Type: "static", Content: "website"})
				options.Detour = detour
				router := &metadataRouter{metadata: make(chan adapter.InboundContext, 1)}
				created, err := naive.NewInbound(context.Background(), router, log.NewNOPFactory().Logger(), "naive-metadata", options)
				if err != nil {
					t.Fatal(err)
				}
				scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
				t.Cleanup(func() { _ = scope.Close() })
				for _, stage := range adapter.ListStartStages {
					if err = created.Start(stage, scope); err != nil {
						t.Fatal(err)
					}
				}
				var transport http.RoundTripper
				address := fmt.Sprintf("127.0.0.1:%d", options.ListenPort)
				requestURL := "https://" + address
				switch protocol {
				case "http1":
					clientTLS.NextProtos = []string{"http/1.1"}
					requestURL = "https://target.example:443"
					tr := &http.Transport{TLSClientConfig: clientTLS, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, "tcp", address)
					}}
					transport = tr
					t.Cleanup(tr.CloseIdleConnections)
				case "http2":
					tr := &http2.Transport{TLSClientConfig: clientTLS}
					transport = tr
					t.Cleanup(tr.CloseIdleConnections)
				case "http3":
					tr := &http3.Transport{TLSClientConfig: clientTLS}
					transport = tr
					t.Cleanup(func() { _ = tr.Close() })
				}
				client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
				request, err := http.NewRequest(http.MethodConnect, requestURL, nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Host = "target.example:443"
				request.Header.Set("Padding", "test")
				request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("a:one")))
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatalf("CONNECT status: %d", response.StatusCode)
				}
				select {
				case metadata := <-router.metadata:
					if metadata.InboundDetour != detour || metadata.Inbound != "naive-metadata" || metadata.InboundType != "naive" || metadata.User != "a" || metadata.Network != "tcp" {
						t.Fatalf("incorrect routing metadata: %+v", metadata)
					}
					if metadata.Destination.String() != "target.example:443" || !metadata.Source.IsValid() {
						t.Fatalf("lost connection addresses: %+v", metadata)
					}
					if protocol == "http1" && metadata.OriginDestination.Port != options.ListenPort {
						t.Fatalf("lost HTTP/1 local endpoint: %s", metadata.OriginDestination)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("CONNECT was not routed")
				}
			})
		}
	}
}
