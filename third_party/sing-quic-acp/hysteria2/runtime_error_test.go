package hysteria2

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

// A read failure can terminate the QUIC accept loop while the supplied UDP
// socket remains open. Exercise the real QUIC transport, not a mocked health
// flag, so the owner can distinguish this state from a healthy bound listener.
func TestServiceReportsTerminalUDPReadFailure(t *testing.T) {
	for _, cause := range []error{syscall.ENETDOWN, syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ECONNREFUSED, net.ErrClosed} {
		t.Run(cause.Error(), func(t *testing.T) {
			serverTLS, _ := testTLSConfigs(t)
			service, err := NewService[string](ServiceOptions{
				Context: context.Background(), Logger: logger.NOP(), TLSConfig: serverTLS,
			})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			wrapped := &failingReadPacketConn{PacketConn: conn, trigger: make(chan struct{}), cause: cause}
			if err := service.Start(wrapped); err != nil {
				t.Fatalf("start: %v", err)
			}
			defer service.Close()
			if err := service.RuntimeError(); err != nil {
				t.Fatalf("healthy listener reported an error: %v", err)
			}
			close(wrapped.trigger)
			deadline := time.Now().Add(testIOTimeout)
			for service.RuntimeError() == nil && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if err := service.RuntimeError(); !errors.Is(err, cause) {
				t.Fatalf("runtime error = %v, want cause %v", err, cause)
			}
			// A successful write proves the socket was not closed with the accept loop.
			if _, err := conn.WriteTo([]byte("still bound"), conn.LocalAddr()); err != nil {
				t.Fatalf("UDP socket should remain open after transport failure: %v", err)
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
			if err := service.RuntimeError(); err != nil {
				t.Fatalf("intentional shutdown reported an error: %v", err)
			}
		})
	}
}

func TestServiceRuntimeErrorIgnoresIntentionalShutdown(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "context cancellation"}[cancelParent], func(t *testing.T) {
			env := startTestService(t, nil, nil)
			if cancelParent {
				env.cancel()
			} else if err := env.service.Close(); err != nil {
				t.Fatal(err)
			}
			if err := env.service.RuntimeError(); err != nil {
				t.Fatalf("normal shutdown reported a listener failure: %v", err)
			}
		})
	}
}

type failingReadPacketConn struct {
	net.PacketConn
	trigger chan struct{}
	cause   error
	failed  atomic.Bool
}

func (c *failingReadPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	if c.failed.CompareAndSwap(false, true) {
		<-c.trigger
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", c.cause)}
	}
	return c.PacketConn.ReadFrom(buffer)
}
