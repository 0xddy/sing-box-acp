package v2rayxhttp

import (
	"io"
	"net"
	"sync"
	"time"
)

// Each HTTP body has its own lifetime. Separate pipe ends provide Go's
// resettable net.Conn deadlines and allow a FIN in one direction without
// discarding buffered traffic in the other.
type streamConn struct {
	reader, writer net.Conn
	local, remote  net.Addr
	once           sync.Once
	onClose        func()
	errMu          sync.Mutex
	readErr        error // published before the read pump closes its pipe
}

func newStream(local, remote net.Addr, onClose func()) (*streamConn, net.Conn, net.Conn) {
	r, input := net.Pipe()
	w, output := net.Pipe()
	return &streamConn{reader: r, writer: w, local: local, remote: remote, onClose: onClose}, input, output
}

func (c *streamConn) receive(input net.Conn, body io.Reader) error {
	_, err := io.Copy(input, body)
	c.failRead(input, err)
	return err
}

func (c *streamConn) setError(err error) {
	if err != nil {
		c.errMu.Lock()
		if c.readErr == nil {
			c.readErr = err
		}
		c.errMu.Unlock()
	}
}

func (c *streamConn) failRead(input net.Conn, err error) { c.setError(err); input.Close() }

func (c *streamConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if err == io.EOF || err == io.ErrClosedPipe {
		c.errMu.Lock()
		defer c.errMu.Unlock()
		if c.readErr != nil {
			return n, c.readErr
		}
	}
	return n, err
}

func (c *streamConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *streamConn) CloseWrite() error { return c.writer.Close() }

func (c *streamConn) Close() error {
	c.once.Do(func() {
		c.reader.Close()
		c.writer.Close()
		c.onClose()
	})
	return nil
}

func (c *streamConn) LocalAddr() net.Addr { return c.local }

func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

func (c *streamConn) SetReadDeadline(t time.Time) error { return c.reader.SetReadDeadline(t) }

func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.writer.SetWriteDeadline(t) }

func (c *streamConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
