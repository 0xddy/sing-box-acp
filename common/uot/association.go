package uot

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

// An association carries independently addressed datagrams. Routing the header
// destination once would let subsequent packets bypass destination rules. Keep
// the existing UoT framing, and give each actual target its own routed UDP flow.
func (r *Router) routeAssociation(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	var access sync.Mutex
	flows := make(map[M.Socksaddr]*associationFlow)
	var pending sync.WaitGroup
	defer func() {
		cancel()
		stop()
		conn.Close()
		access.Lock()
		active := make([]*associationFlow, 0, len(flows))
		for _, flow := range flows {
			active = append(active, flow)
		}
		access.Unlock()
		for _, flow := range active {
			flow.Close()
		}
		pending.Wait()
	}()
	for {
		packet := buf.NewPacket()
		target, err := conn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			return err
		}
		if !target.IsValid() || target.Port == 0 {
			packet.Release()
			continue
		}
		access.Lock()
		flow := flows[target]
		created := false
		if flow == nil && len(flows) < 256 {
			flow = &associationFlow{writer: conn, source: metadata.Source, target: target, packets: make(chan *buf.Buffer, 8), done: make(chan struct{}), deadline: pipe.MakeDeadline()}
			flow.remove = func() {
				access.Lock()
				if flows[target] == flow {
					delete(flows, target)
				}
				access.Unlock()
			}
			flows[target] = flow
			created = true
		}
		access.Unlock()
		if flow == nil {
			packet.Release()
			continue
		}
		flow.enqueue(packet)
		if created {
			flowMetadata := metadata
			flowMetadata.Destination = target
			flowMetadata.Domain = target.Fqdn
			flowMetadata.RequestedDestination = target
			pending.Add(1)
			go r.router.RoutePacketConnectionEx(ctx, flow, flowMetadata, N.OnceClose(func(error) {
				flow.Close()
				pending.Done()
			}))
		}
	}
}

type associationFlow struct {
	writer         N.PacketWriter
	source, target M.Socksaddr
	access         sync.Mutex
	packets        chan *buf.Buffer
	done           chan struct{}
	closed         bool
	deadline       pipe.Deadline
	remove         func()
}

func (c *associationFlow) enqueue(packet *buf.Buffer) {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.closed {
		select {
		case c.packets <- packet:
			return
		default:
		}
	}
	packet.Release()
}

func (c *associationFlow) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case <-c.done:
		return M.Socksaddr{}, net.ErrClosed
	default:
	}
	select {
	case packet := <-c.packets:
		_, err := buffer.Write(packet.Bytes())
		packet.Release()
		return c.target, err
	case <-c.done:
		return M.Socksaddr{}, net.ErrClosed
	case <-c.deadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *associationFlow) WritePacket(buffer *buf.Buffer, target M.Socksaddr) error {
	select {
	case <-c.done:
		buffer.Release()
		return net.ErrClosed
	default:
		return c.writer.WritePacket(buffer, target)
	}
}

func (c *associationFlow) Close() error {
	c.access.Lock()
	if c.closed {
		c.access.Unlock()
		return nil
	}
	c.closed = true
	close(c.done)
	for {
		select {
		case packet := <-c.packets:
			packet.Release()
		default:
			c.access.Unlock()
			c.remove()
			return nil
		}
	}
}

func (c *associationFlow) LocalAddr() net.Addr                { return c.source }
func (c *associationFlow) SetDeadline(time.Time) error        { return os.ErrInvalid }
func (c *associationFlow) SetWriteDeadline(time.Time) error   { return os.ErrInvalid }
func (c *associationFlow) SetReadDeadline(at time.Time) error { c.deadline.Set(at); return nil }
