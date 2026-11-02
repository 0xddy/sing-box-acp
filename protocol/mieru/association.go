package mieru

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"
)

// One Mieru association can mix address families and routing policies. Keep
// a bounded queue per destination; replies share the original framed stream.
func (h *Inbound) routeAssociation(ctx context.Context, pc *packetConn, metadata adapter.InboundContext, timeout time.Duration) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	routes := make(map[M.Socksaddr]*destinationConn)
	payload := make([]byte, 65535)
	for {
		pc.SetReadDeadline(time.Now().Add(timeout))
		n, addr, err := pc.ReadFrom(payload)
		if err != nil {
			return err
		}
		dst := M.SocksaddrFromNet(addr).Unwrap()
		route := routes[dst]
		if route == nil || route.ctx.Err() != nil {
			if len(routes) >= 256 {
				for key, r := range routes {
					if r.ctx.Err() != nil {
						delete(routes, key)
					}
				}
				if len(routes) >= 256 {
					continue
				}
			}
			routeCtx, stop := context.WithCancel(ctx)
			route = &destinationConn{
				ctx: routeCtx, cancel: stop, packets: make(chan []byte, 32),
				dst: dst, stream: pc, timeout: timeout,
				readDeadline: pipe.MakeDeadline(), writeDeadline: pipe.MakeDeadline(),
			}
			routes[dst] = route
			info := metadata
			info.Destination = dst
			go h.router.RoutePacketConnectionEx(routeCtx, addressedConn{route}, info, func(error) { stop() })
		}
		select {
		case route.packets <- append([]byte(nil), payload[:n]...):
		default:
		}
	}
}

type destinationConn struct {
	ctx                         context.Context
	cancel                      context.CancelFunc
	dst                         M.Socksaddr
	stream                      *packetConn
	timeout                     time.Duration
	packets                     chan []byte
	readDeadline, writeDeadline pipe.Deadline
}

func (c *destinationConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case data := <-c.packets:
		if c.ctx.Err() != nil {
			return 0, nil, net.ErrClosed
		}
		return copy(p, data), c.dst, nil
	}
}
func (c *destinationConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	case <-c.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	c.stream.SetReadDeadline(time.Now().Add(c.timeout))
	return c.stream.WriteTo(p, addr)
}
func (c *destinationConn) Close() error        { c.cancel(); c.SetDeadline(time.Time{}); return nil }
func (c *destinationConn) LocalAddr() net.Addr { return c.stream.LocalAddr() }
func (c *destinationConn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	c.writeDeadline.Set(t)
	return nil
}
func (c *destinationConn) SetReadDeadline(t time.Time) error  { c.readDeadline.Set(t); return nil }
func (c *destinationConn) SetWriteDeadline(t time.Time) error { c.writeDeadline.Set(t); return nil }
