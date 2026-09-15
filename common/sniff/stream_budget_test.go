package sniff

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
)

type budgetStreamConn struct {
	deadline      time.Time
	deadlines     []time.Time
	reads         int
	deadlineError error
}

func (c *budgetStreamConn) Read(p []byte) (int, error) {
	c.reads++
	if remaining := time.Until(c.deadline); remaining < 20*time.Millisecond {
		time.Sleep(max(remaining, 0))
		return 0, os.ErrDeadlineExceeded
	}
	time.Sleep(20 * time.Millisecond)
	p[0] = byte('a' + c.reads - 1)
	return 1, nil
}
func (c *budgetStreamConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *budgetStreamConn) Close() error                     { return nil }
func (c *budgetStreamConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *budgetStreamConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *budgetStreamConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
func (c *budgetStreamConn) SetWriteDeadline(time.Time) error { return nil }
func (c *budgetStreamConn) SetReadDeadline(t time.Time) error {
	if c.deadlineError != nil {
		return c.deadlineError
	}
	c.deadline = t
	if !t.IsZero() {
		c.deadlines = append(c.deadlines, t)
	}
	return nil
}

func TestStreamSniffUsesOneAbsoluteReadBudgetAndRetainsPayload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := &budgetStreamConn{}
		buffer := buf.NewPacket()
		defer buffer.Release()
		started := time.Now()
		err := PeekStream(context.Background(), &adapter.InboundContext{}, conn, nil, buffer, 50*time.Millisecond, func(context.Context, *adapter.InboundContext, io.Reader) error { return ErrNeedMoreData })
		if err == nil {
			t.Fatal("incomplete protocol unexpectedly recognized")
		}
		if len(conn.deadlines) < 2 {
			t.Fatal("did not exercise multiple reads")
		}
		for _, deadline := range conn.deadlines {
			if !deadline.Equal(conn.deadlines[0]) {
				t.Fatal("read extended the sniff budget")
			}
		}
		if time.Since(started) > 500*time.Millisecond {
			t.Fatal("sniff failed to terminate within its budget")
		}
		if string(buffer.Bytes()) != "ab" {
			t.Fatalf("prefetched payload changed: %q", buffer.Bytes())
		}
		if !conn.deadline.IsZero() {
			t.Fatal("sniff left the business read deadline installed")
		}
	})
}
func TestStreamSniffDeadlineFailureDoesNotReadOrConsumeCache(t *testing.T) {
	conn := &budgetStreamConn{deadlineError: errors.New("unsupported deadline")}
	buffer := buf.NewPacket()
	defer buffer.Release()
	_, _ = buffer.Write([]byte("cached"))
	err := PeekStream(context.Background(), &adapter.InboundContext{}, conn, nil, buffer, time.Second, func(context.Context, *adapter.InboundContext, io.Reader) error { return nil })
	if err == nil || conn.reads != 0 || string(buffer.Bytes()) != "cached" {
		t.Fatalf("err=%v reads=%d buffer=%q", err, conn.reads, buffer.Bytes())
	}
}
