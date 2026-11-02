package juicity

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

// Keep domain destinations intact when crossing sing's packet API.
type namedPackets struct{ net.PacketConn }

func asPacketConn(c net.PacketConn) N.NetPacketConn { return namedPackets{c} }

func (c namedPackets) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	_, addr, err := b.ReadPacketFrom(c.PacketConn)
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.SocksaddrFromNet(addr).Unwrap(), nil
}

func (c namedPackets) WritePacket(b *buf.Buffer, d M.Socksaddr) error {
	defer b.Release()
	_, err := c.WriteTo(b.Bytes(), d)
	return err
}

type datagram struct {
	data    []byte
	address M.Socksaddr
}

type packetInbox struct {
	ctx                         context.Context
	cancel                      context.CancelFunc
	packets                     chan datagram
	readDeadline, writeDeadline pipe.Deadline
}

func newPacketInbox(parent context.Context) *packetInbox {
	ctx, cancel := context.WithCancel(parent)
	return &packetInbox{ctx: ctx, cancel: cancel, packets: make(chan datagram, 32), readDeadline: pipe.MakeDeadline(), writeDeadline: pipe.MakeDeadline()}
}

func (q *packetInbox) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-q.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-q.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case pkt := <-q.packets:
		if q.ctx.Err() != nil {
			return 0, nil, net.ErrClosed
		}
		return copy(p, pkt.data), pkt.address, nil
	}
}

func (q *packetInbox) writable() error {
	select {
	case <-q.ctx.Done():
		return net.ErrClosed
	case <-q.writeDeadline.Wait():
		return os.ErrDeadlineExceeded
	default:
		return nil
	}
}

func (q *packetInbox) Close() error {
	q.cancel()
	q.readDeadline.Set(time.Time{})
	q.writeDeadline.Set(time.Time{})
	return nil
}

func (q *packetInbox) SetReadDeadline(t time.Time) error { q.readDeadline.Set(t); return nil }

func (q *packetInbox) SetWriteDeadline(t time.Time) error { q.writeDeadline.Set(t); return nil }

func (q *packetInbox) SetDeadline(t time.Time) error {
	q.readDeadline.Set(t)
	q.writeDeadline.Set(t)
	return nil
}
