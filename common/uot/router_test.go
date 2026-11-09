package uot

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

type captureRouter struct {
	adapter.ConnectionRouterEx
	metadata adapter.InboundContext
}

type associationRouter struct {
	adapter.ConnectionRouterEx
	observed chan adapter.InboundContext
	keepOpen bool
}

func (r *associationRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	done := make(chan struct{})
	r.RoutePacketConnectionEx(ctx, conn, metadata, func(error) { close(done) })
	<-done
	return nil
}

func (r *associationRouter) RoutePacketConnectionEx(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		defer onClose(nil)
		packet := buf.NewPacket()
		defer packet.Release()
		if _, err := conn.ReadPacket(packet); err == nil {
			r.observed <- metadata
		}
		if r.keepOpen {
			for {
				packet.Reset()
				if _, err := conn.ReadPacket(packet); err != nil {
					return
				}
			}
		}
	}()
}

func TestUoTAssociationCancellationClosesActiveTargets(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	capture := &associationRouter{observed: make(chan adapter.InboundContext, 2), keepOpen: true}
	router := NewRouter(capture, log.NewNOPFactory().Logger())
	done := make(chan struct{})
	go router.RouteConnectionEx(ctx, server, adapter.InboundContext{Destination: M.Socksaddr{Fqdn: uot.MagicAddress}}, func(error) { close(done) })
	request := uot.Request{Destination: M.ParseSocksaddr("ignored.example:53")}
	if err := uot.WriteRequest(client, request); err != nil {
		t.Fatal(err)
	}
	conn := uot.NewConn(client, request)
	for _, target := range []string{"192.0.2.1:53", "192.0.2.2:53"} {
		if _, err := conn.WriteTo(nil, M.ParseSocksaddr(target)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-capture.observed:
		case <-time.After(3 * time.Second):
			t.Fatal("flow not started")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not drain active flows")
	}
}

func TestUoTAssociationRoutesEveryActualTarget(t *testing.T) {
	for _, extended := range []bool{false, true} {
		t.Run(map[bool]string{true: "ex", false: "sync"}[extended], func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			routed := &associationRouter{observed: make(chan adapter.InboundContext, 2)}
			router := NewRouter(routed, log.NewNOPFactory().Logger())
			done := make(chan struct{})
			go func() {
				metadata := adapter.InboundContext{Destination: M.Socksaddr{Fqdn: uot.MagicAddress}, Domain: uot.MagicAddress, User: "21", Inbound: "node"}
				if extended {
					router.RouteConnectionEx(context.Background(), server, metadata, func(error) { close(done) })
				} else {
					router.RouteConnection(context.Background(), server, metadata)
					close(done)
				}
			}()
			request := uot.Request{Destination: M.ParseSocksaddr("header.example:53")}
			if err := uot.WriteRequest(client, request); err != nil {
				t.Fatal(err)
			}
			conn := uot.NewConn(client, request)
			for _, target := range []string{"192.0.2.1:1234", "blocked.example:53"} {
				destination := M.ParseSocksaddr(target)
				if _, err := conn.WriteTo([]byte("packet"), destination); err != nil {
					t.Fatal(err)
				}
				select {
				case metadata := <-routed.observed:
					if metadata.Destination != destination || metadata.Domain != destination.Fqdn || metadata.User != "21" || metadata.Inbound != "node" {
						t.Fatalf("packet target %v bypassed routing: %+v", destination, metadata)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("target not routed")
				}
			}
			client.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("association not closed")
			}
		})
	}
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
