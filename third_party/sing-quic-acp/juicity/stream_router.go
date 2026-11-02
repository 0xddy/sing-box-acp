package juicity

import (
	"context"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// A single Juicity stream can carry both IP families and domain names.
// Let the router select the policy, resolver and socket for each destination.
func (s *serverSession) routePackets(ctx context.Context, stream *streamConn, source M.Socksaddr) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer stream.Close()
	packets := &streamPackets{streamConn: stream}
	routes := make(map[M.Socksaddr]*routedPackets)
	buf := make([]byte, maxPayload)
	for {
		_ = stream.SetReadDeadline(time.Now().Add(s.options.UDPTimeout))
		n, addr, err := packets.ReadFrom(buf)
		if err != nil {
			return
		}
		dst := M.SocksaddrFromNet(addr)
		route := routes[dst]
		if route == nil || route.ctx.Err() != nil {
			if len(routes) >= maxAssociations {
				for d, r := range routes {
					if r.ctx.Err() != nil {
						delete(routes, d)
					}
				}
				if len(routes) >= maxAssociations {
					continue
				}
			}
			route = &routedPackets{packetInbox: newPacketInbox(ctx), stream: packets, idle: s.options.UDPTimeout}
			routes[dst] = route
			go s.options.Handler.NewPacketConnectionEx(route.ctx, asPacketConn(route), source, dst, nil)
		}
		packet := datagram{append([]byte(nil), buf[:n]...), dst}
		select {
		case route.packets <- packet:
		case <-route.ctx.Done():
		case <-stream.Context().Done():
			return
		case <-ctx.Done():
			return
		}
	}
}

type routedPackets struct {
	*packetInbox
	stream *streamPackets
	idle   time.Duration
}

func (p *routedPackets) LocalAddr() net.Addr { return p.stream.LocalAddr() }

func (p *routedPackets) WriteTo(data []byte, src net.Addr) (int, error) {
	if err := p.writable(); err != nil {
		return 0, err
	}
	_ = p.stream.SetReadDeadline(time.Now().Add(p.idle))
	return p.stream.WriteTo(data, src)
}
