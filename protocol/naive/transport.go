package naive

import (
	"net"
	"sync"
)

// AcquireTransport is shared by TCP and the HTTP/3 adapter.
func (n *Inbound) AcquireTransport() (func(), bool) {
	n.mu.Lock()
	if n.closed || n.transportCount >= MaxTransportConnections {
		n.mu.Unlock()
		return nil, false
	}
	n.transportCount++
	n.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { n.mu.Lock(); n.transportCount--; n.mu.Unlock() }) }, true
}

type transportConn struct {
	net.Conn
	owner   *Inbound
	release func()
	once    sync.Once
}

func (n *Inbound) ownTransport(conn net.Conn) *transportConn {
	release, ok := n.AcquireTransport()
	if !ok {
		return nil
	}
	c := &transportConn{Conn: conn, owner: n, release: release}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		release()
		return nil
	}
	n.transports[c] = struct{}{}
	n.mu.Unlock()
	return c
}
func (c *transportConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.transports, c)
		c.owner.mu.Unlock()
		c.release()
	})
	return err
}

type boundedListener struct {
	net.Listener
	owner *Inbound
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if c := l.owner.ownTransport(conn); c != nil {
			return c, nil
		}
		_ = conn.Close()
	}
}
