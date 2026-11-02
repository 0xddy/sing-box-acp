package juicity

import (
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	M "github.com/sagernet/sing/common/metadata"
)

// streamConn owns one bidirectional stream; closing it must not abort its siblings.
type streamConn struct {
	*quic.Stream
	connection *quic.Conn
	release    func()
	once       sync.Once
}

func (c *streamConn) LocalAddr() net.Addr { return c.connection.LocalAddr() }

func (c *streamConn) RemoteAddr() net.Addr { return c.connection.RemoteAddr() }

func (c *streamConn) CloseWrite() error { return c.Stream.Close() }

func (c *streamConn) Close() error {
	c.once.Do(func() {
		c.CancelRead(0)
		_ = c.Stream.Close()
		_ = c.SetWriteDeadline(time.Now())
		if c.release != nil {
			c.release()
		}
	})
	return nil
}

type streamPackets struct {
	*streamConn
	readMu, writeMu sync.Mutex
}

func (c *streamPackets) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	n, dst, err := readPacket(c.Stream, p)
	return n, dst, err
}

func (c *streamPackets) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writePacket(c.Stream, p, M.SocksaddrFromNet(addr))
}
