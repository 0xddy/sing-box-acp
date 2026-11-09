package uot

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

type captureRouter struct {
	adapter.ConnectionRouterEx
	metadata adapter.InboundContext
}

func (r *captureRouter) RoutePacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	r.metadata = metadata
	return conn.Close()
}

func (r *captureRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, close N.CloseHandlerFunc) {
	err := r.RoutePacketConnection(ctx, conn, metadata)
	if close != nil {
		close(err)
	}
}

func TestUoTRoutingUsesRealDestination(t *testing.T) {
	for _, target := range []string{"private.example:53", "192.0.2.1:53", "[2001:db8::1]:53"} {
		for _, extended := range []bool{false, true} {
			t.Run(target+map[bool]string{true: "/ex", false: "/sync"}[extended], func(t *testing.T) {
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				destination := M.ParseSocksaddr(target)
				written := make(chan error, 1)
				go func() { written <- uot.WriteRequest(client, uot.Request{IsConnect: true, Destination: destination}) }()
				capture := &captureRouter{}
				router := NewRouter(capture, log.NewNOPFactory().Logger())
				metadata := adapter.InboundContext{Destination: M.Socksaddr{Fqdn: uot.MagicAddress}, User: "21", Inbound: "node"}
				if extended {
					router.RouteConnectionEx(context.Background(), server, metadata, nil)
				} else if err := router.RouteConnection(context.Background(), server, metadata); err != nil {
					t.Fatal(err)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
				got := capture.metadata
				if got.Destination != destination || got.Domain != destination.Fqdn || got.User != "21" || got.Inbound != "node" {
					t.Fatalf("UoT lost destination or identity: %+v", got)
				}
			})
		}
	}
}
