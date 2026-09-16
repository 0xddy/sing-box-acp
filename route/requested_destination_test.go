package route

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
)

type requestedDestinationTransports struct {
	adapter.DNSTransportManager
}

func (requestedDestinationTransports) FakeIP() adapter.FakeIPTransport { return nil }

func TestRequestedDestinationSurvivesRoutingOverrides(t *testing.T) {
	for _, address := range []string{"192.0.2.1:443", "requested.example.com:443"} {
		t.Run(address, func(t *testing.T) {
			original := M.ParseSocksaddr(address)
			metadata := adapter.InboundContext{Destination: original, Domain: "routing-hint.example.com"}
			router := Router{dnsTransport: requestedDestinationTransports{}}
			if err := router.prepareMatchMetadata(context.Background(), &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata.RequestedDestination != original {
				t.Fatalf("request target not captured: %+v", metadata)
			}
			applyRouteOptionsOverride(&metadata, &R.RuleActionRouteOptions{
				OverrideAddress: M.ParseSocksaddr("outer.example.com:443"),
				OverridePort:    8443,
			})
			if err := router.prepareMatchMetadata(context.Background(), &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata.RequestedDestination != original || metadata.Destination != M.ParseSocksaddr("outer.example.com:8443") {
				t.Fatalf("routing override changed request facts: %+v", metadata)
			}
		})
	}
}
