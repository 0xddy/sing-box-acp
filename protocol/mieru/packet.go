package mieru

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"

	api "github.com/enfein/mieru/v3/apis/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// The official tunnel preserves datagram boundaries. Keep SOCKS addresses
// intact so the router, including its DNS rules, sees the original destination.
type packetConn struct {
	*api.PacketOverStreamTunnel
	readMu, writeMu sync.Mutex
}

// Preserve domain addresses on both sing and standard net.PacketConn paths.
type addressedConn struct{ net.PacketConn }

func (c addressedConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	_, addr, err := b.ReadPacketFrom(c.PacketConn)
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.SocksaddrFromNet(addr).Unwrap(), nil
}
func (c addressedConn) WritePacket(b *buf.Buffer, dst M.Socksaddr) error {
	defer b.Release()
	_, err := c.WriteTo(b.Bytes(), dst)
	return err
}

func newPacketConn(conn net.Conn) *packetConn {
	return &packetConn{PacketOverStreamTunnel: api.NewPacketOverStreamTunnel(conn)}
}

func (c *packetConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	frame := buf.NewSize(65535)
	defer frame.Release()
	n, err := c.PacketOverStreamTunnel.Read(frame.FreeBytes())
	if err != nil {
		return 0, nil, err
	}
	frame.Truncate(n)
	header, err := frame.ReadBytes(3)
	if err != nil {
		return 0, nil, err
	}
	if header[0] != 0 || header[1] != 0 || header[2] != 0 {
		return 0, nil, fmt.Errorf("invalid or fragmented SOCKS datagram")
	}
	dst, err := M.SocksaddrSerializer.ReadAddrPort(frame)
	if err != nil {
		return 0, nil, err
	}
	if dst.IsDomain() {
		return copy(payload, frame.Bytes()), dst, nil
	}
	return copy(payload, frame.Bytes()), dst.UDPAddr(), nil
}

func (c *packetConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	dst := M.SocksaddrFromNet(addr)
	size := 3 + M.SocksaddrSerializer.AddrPortLen(dst) + len(payload)
	if size > 65535 {
		return 0, io.ErrShortBuffer
	}
	frame := bytes.NewBuffer(make([]byte, 3, size))
	if err := M.SocksaddrSerializer.WriteAddrPort(frame, dst); err != nil {
		return 0, err
	}
	frame.Write(payload)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.PacketOverStreamTunnel.Write(frame.Bytes()); err != nil {
		return 0, err
	}
	return len(payload), nil
}
