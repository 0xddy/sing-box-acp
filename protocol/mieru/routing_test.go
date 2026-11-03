package mieru_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	M "github.com/sagernet/sing/common/metadata"
)

func routingBox(t *testing.T, ctx context.Context, rules string) *box.Box {
	t.Helper()
	socket, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := socket.Addr().(*net.TCPAddr).Port
	socket.Close()
	raw := fmt.Sprintf(`{"inbounds":[{"type":"mieru","tag":"entry","listen":"127.0.0.1","listen_port":%[1]d,"users":[{"name":"alice","password":"secret"}]}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"mieru","tag":"standard","server":"127.0.0.1","server_port":%[1]d,"username":"alice","password":"secret"},{"type":"mieru","tag":"early","server":"127.0.0.1","server_port":%[1]d,"username":"alice","password":"secret","handshake_mode":"no_wait"}],"route":{"rules":%[2]s,"final":"direct"}}`, port, rules)
	instance, err := configured(include.Context(ctx), raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance
}

func TestSniffPreservesConnectResultAndEarlyData(t *testing.T) {
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()
	// Only sniffed HTTP reaches the echo server. A different port routes to
	// direct so its actual connection refusal must reach the standard client.
	port := echo.Addr().(*net.TCPAddr).Port
	rules := fmt.Sprintf(`[{"action":"sniff"},{"protocol":"http","outbound":"direct"},{"port":%d,"action":"reject"}]`, port)
	instance := routingBox(t, t.Context(), rules)
	closed, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dst := M.SocksaddrFromNet(closed.Addr())
	closed.Close()
	client, _ := instance.Outbound().Outbound("standard")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if conn, err := client.DialContext(ctx, "tcp", dst); err == nil {
		conn.Close()
		t.Fatal("standard CONNECT acknowledged a refused destination")
	} else if !strings.Contains(err.Error(), "socks5 error code 5") {
		t.Fatalf("missing connection refusal: %v", err)
	}
	client, _ = instance.Outbound().Outbound("early")
	const request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	refused, err := client.DialContext(ctx, "tcp", dst)
	if err != nil {
		t.Fatal(err)
	}
	defer refused.Close()
	if _, err = io.WriteString(refused, request); err == nil || !strings.Contains(err.Error(), "socks5 error code 5") {
		t.Fatalf("sniffing early data acknowledged a refused destination: %v", err)
	}
	conn, err := client.DialContext(ctx, "tcp", M.SocksaddrFromNet(echo.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(request))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != request {
		t.Fatalf("early payload: %q, %v", got, err)
	}
}

// Models a pending route waiting for the agent's configuration commit.
type waitingTracker struct {
	adapter.ConnectionTracker
	entered chan struct{}
}

func (w waitingTracker) RoutedConnection(ctx context.Context, conn net.Conn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	close(w.entered)
	<-ctx.Done()
	return conn
}

func TestRemoveInboundCancelsPendingRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	instance := routingBox(t, ctx, "[]")
	tracker := waitingTracker{entered: make(chan struct{})}
	instance.Router().AppendTracker(tracker)
	client, _ := instance.Outbound().Outbound("standard")
	go func() {
		if conn, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:1")); err == nil {
			conn.Close()
		}
	}()
	select {
	case <-tracker.entered:
	case <-time.After(4 * time.Second):
		t.Fatal("route did not reach tracker")
	}
	removed := make(chan error, 1)
	go func() { removed <- instance.Inbound().Remove("entry") }()
	select {
	case err := <-removed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		cancel() // release the parent as well if the regression returns
		<-removed
		t.Fatal("removing Mieru waited for the whole instance to shut down")
	}
}
