package naive

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
)

// HTTPStream owns only one CONNECT stream, never its multiplexed connection.
// The write barrier prevents ResponseWriter use after ServeHTTP returns.
type httpStream struct {
	*naiveH2Conn
	controller  *http.ResponseController
	bodyClose   func() error
	writeMu     sync.Mutex
	deadlineMu  sync.Mutex
	interrupted bool
	closed      atomic.Bool
}

func newHTTPStream(r *http.Request, w http.ResponseWriter, controller *http.ResponseController, source net.Addr) *httpStream {
	return &httpStream{
		naiveH2Conn: &naiveH2Conn{reader: r.Body, writer: w, flusher: w.(http.Flusher), remoteAddress: source},
		controller:  controller, bodyClose: r.Body.Close,
	}
}
func (c *httpStream) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.deadlineMu.Lock()
	if c.closed.Load() {
		c.deadlineMu.Unlock()
		return 0, net.ErrClosed
	}
	_ = c.controller.SetWriteDeadline(time.Now().Add(2 * time.Minute))
	c.deadlineMu.Unlock()
	defer func() {
		c.deadlineMu.Lock()
		defer c.deadlineMu.Unlock()
		// A write deadline protects pending I/O, not the following idle period.
		if !c.closed.Load() {
			_ = c.controller.SetWriteDeadline(time.Time{})
		}
	}()
	return c.naiveH2Conn.Write(p)
}

func (c *httpStream) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.naiveH2Conn.Read(p)
}
func (c *httpStream) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	_, err := c.Write(buffer.Bytes())
	return err
}
func (c *httpStream) Close() error {
	c.closed.Store(true)
	_ = c.controller.SetReadDeadline(time.Now())
	// A completed writer has already flushed its final bytes. Expiring its
	// deadline here would reset the stream before net/http writes END_STREAM.
	// An in-progress writer must still be interrupted before the handler exits.
	if !c.writeMu.TryLock() {
		c.interruptWrite()
		c.writeMu.Lock()
	}
	c.writeMu.Unlock()
	err := c.bodyClose()
	return err
}

func (c *httpStream) abort() error {
	c.interruptWrite()
	return c.Close()
}

func (c *httpStream) interruptWrite() {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	c.closed.Store(true)
	if !c.interrupted {
		c.interrupted = true
		_ = c.controller.SetWriteDeadline(time.Now())
	}
}

// Hide the optimized writer methods of naiveH2Conn: they would skip the barrier.
func (c *httpStream) Upstream() any           { return nil }
func (c *httpStream) WriterReplaceable() bool { return false }
func (c *httpStream) ReaderReplaceable() bool { return false }

// HTTP/1 CONNECT owns the entire hijacked connection, so its write protection
// can use socket deadlines. Never apply this wrapper to a multiplexed stream.
type writeProgressConn struct{ net.Conn }

func (c *writeProgressConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Minute))
	defer c.Conn.SetWriteDeadline(time.Time{})
	return c.Conn.Write(p)
}
