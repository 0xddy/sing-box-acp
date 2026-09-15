package route

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type sniffTestPacketConn struct {
	targets             []M.Socksaddr
	data                []byte
	delay               time.Duration
	deadline            time.Time
	deadlineErr         error
	reads, deadlineSets int
	closed              chan struct{}
	closeOnce           sync.Once
}

func (c *sniffTestPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.reads++
	wait := c.delay
	timedOut := false
	if remaining := time.Until(c.deadline); !c.deadline.IsZero() && remaining < wait {
		wait, timedOut = remaining, true
	}
	timer := time.NewTimer(max(wait, 0))
	defer timer.Stop()
	select {
	case <-c.closed:
		return M.Socksaddr{}, net.ErrClosed
	case <-timer.C:
	}
	if timedOut {
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
	if len(c.targets) == 0 {
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
	_, err := buffer.Write(c.data)
	target := c.targets[0]
	if len(c.targets) > 1 {
		c.targets = c.targets[1:]
	}
	return target, err
}
func (c *sniffTestPacketConn) WritePacket(*buf.Buffer, M.Socksaddr) error { return nil }
func (c *sniffTestPacketConn) Close() error                               { c.closeOnce.Do(func() { close(c.closed) }); return nil }
func (c *sniffTestPacketConn) LocalAddr() net.Addr                        { return &net.UDPAddr{} }
func (c *sniffTestPacketConn) SetDeadline(deadline time.Time) error {
	return c.SetReadDeadline(deadline)
}
func (c *sniffTestPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *sniffTestPacketConn) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.deadlineSets++
	}
	c.deadline = deadline
	return c.deadlineErr
}

func releaseSniffPackets(packets []*N.PacketBuffer) {
	for _, packet := range packets {
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
	}
}

func TestPacketSniffTotalDeadlinePreservesConnectionAndPayload(t *testing.T) {
	conn := &sniffTestPacketConn{targets: []M.Socksaddr{M.ParseSocksaddr("192.0.2.1:443")}, data: []byte("fragment"), delay: 20 * time.Millisecond, closed: make(chan struct{})}
	metadata := adapter.InboundContext{}
	packets, err := sniffPacketConnection(context.Background(), &metadata, &R.RuleActionSniff{Timeout: 55 * time.Millisecond}, conn, nil, []sniff.PacketSniffer{func(context.Context, *adapter.InboundContext, []byte) error { return sniff.ErrNeedMoreData }})
	defer releaseSniffPackets(packets)
	if err != nil || conn.deadlineSets != 1 || conn.reads >= maxSniffPackets || len(packets) == 0 {
		t.Fatalf("err=%v reads=%d packets=%d deadlines=%d", err, conn.reads, len(packets), conn.deadlineSets)
	}
	select {
	case <-conn.closed:
		t.Fatal("sniff timeout closed business connection")
	default:
	}
	for _, packet := range packets {
		if string(packet.Buffer.Bytes()) != "fragment" {
			t.Fatal("payload was lost")
		}
	}
	if metadata.SniffContext != nil || metadata.SniffDestination.IsValid() {
		t.Fatal("failed sniff retained attribution")
	}
}

func TestPacketSniffPacketAndByteBudgets(t *testing.T) {
	for _, dataSize := range []int{1, buf.UDPBufferSize} {
		conn := &sniffTestPacketConn{targets: []M.Socksaddr{M.ParseSocksaddr("192.0.2.1:443")}, data: make([]byte, dataSize), closed: make(chan struct{})}
		var metadata adapter.InboundContext
		packets, err := sniffPacketConnection(context.Background(), &metadata, &R.RuleActionSniff{}, conn, nil, []sniff.PacketSniffer{func(context.Context, *adapter.InboundContext, []byte) error { return sniff.ErrNeedMoreData }})
		releaseSniffPackets(packets)
		want := min(maxSniffPackets, maxSniffPacketBytes/dataSize)
		if err != nil || conn.reads != want {
			t.Fatalf("size=%d err=%v reads=%d want=%d", dataSize, err, conn.reads, want)
		}
	}
}

func TestPacketSniffDoesNotMixTargets(t *testing.T) {
	conn := &sniffTestPacketConn{targets: []M.Socksaddr{M.ParseSocksaddr("192.0.2.1:443"), M.ParseSocksaddr("192.0.2.2:443")}, data: []byte("fragment"), closed: make(chan struct{})}
	var metadata adapter.InboundContext
	called := 0
	packets, err := sniffPacketConnection(context.Background(), &metadata, &R.RuleActionSniff{}, conn, nil, []sniff.PacketSniffer{func(context.Context, *adapter.InboundContext, []byte) error { called++; return sniff.ErrNeedMoreData }})
	defer releaseSniffPackets(packets)
	if err != nil || called != 1 || len(packets) != 2 || metadata.SniffDestination.IsValid() {
		t.Fatalf("err=%v calls=%d packets=%d", err, called, len(packets))
	}
}

func TestPacketSniffTargetAttributionAndUnsupportedDeadline(t *testing.T) {
	target := M.ParseSocksaddr("192.0.2.1:443")
	conn := &sniffTestPacketConn{targets: []M.Socksaddr{target}, data: []byte("hello"), closed: make(chan struct{})}
	metadata := adapter.InboundContext{User: "user-1", Domain: "sp.udp-over-tcp.arpa"}
	packets, err := sniffPacketConnection(context.Background(), &metadata, &R.RuleActionSniff{}, conn, nil, []sniff.PacketSniffer{func(_ context.Context, metadata *adapter.InboundContext, _ []byte) error {
		metadata.Domain, metadata.Protocol = "example.com", "quic"
		metadata.SniffDomain = metadata.Domain
		return nil
	}})
	releaseSniffPackets(packets)
	if err != nil || metadata.SniffDestination != target || metadata.Domain != "example.com" || metadata.SniffDomain != "example.com" || metadata.User != "user-1" {
		t.Fatalf("err=%v metadata=%+v", err, metadata)
	}
	conn.deadlineErr = os.ErrInvalid
	conn.reads = 0
	_, err = sniffPacketConnection(context.Background(), &metadata, &R.RuleActionSniff{}, conn, nil, nil)
	if err != nil || conn.reads != 0 || metadata.SniffDestination.IsValid() {
		t.Fatal("unsupported deadline waited or retained attribution")
	}
}

func TestPacketProtocolOnlySniffDoesNotClaimReverseDNSDomain(t *testing.T) {
	target := M.ParseSocksaddr("192.0.2.1:123")
	conn := &sniffTestPacketConn{targets: []M.Socksaddr{target}, data: []byte("payload"), closed: make(chan struct{})}
	metadata := adapter.InboundContext{Destination: target, Domain: "reverse.example.com"}
	packets, err := sniffPacketConnection(context.Background(), &metadata, &R.RuleActionSniff{}, conn, nil, []sniff.PacketSniffer{func(_ context.Context, metadata *adapter.InboundContext, _ []byte) error {
		metadata.Protocol = "ntp"
		return nil
	}})
	defer releaseSniffPackets(packets)
	if err != nil || metadata.Domain != "reverse.example.com" || metadata.SniffDomain != "" || metadata.SniffDestination != target {
		t.Fatalf("business hint changed or falsely attributed to payload: err=%v metadata=%+v", err, metadata)
	}
}

func TestPacketSniffCachedPayloadIsNotReturnedTwice(t *testing.T) {
	target := M.ParseSocksaddr("192.0.2.1:443")
	cached := N.NewPacketBuffer()
	cached.Buffer, cached.Destination = buf.NewPacket(), target
	_, _ = cached.Buffer.WriteString("cached")
	defer releaseSniffPackets([]*N.PacketBuffer{cached})
	conn := &sniffTestPacketConn{closed: make(chan struct{})}
	var metadata adapter.InboundContext
	packets, err := sniffPacketConnection(context.Background(), &metadata, &R.RuleActionSniff{}, conn, []*N.PacketBuffer{cached}, []sniff.PacketSniffer{func(_ context.Context, metadata *adapter.InboundContext, _ []byte) error {
		metadata.Protocol = "quic"
		return nil
	}})
	if err != nil || len(packets) != 0 || conn.reads != 0 || string(cached.Buffer.Bytes()) != "cached" || metadata.SniffDestination != target {
		t.Fatalf("err=%v new packets=%d reads=%d", err, len(packets), conn.reads)
	}
}

func TestPacketSniffParentCancellationClosesBusinessConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &sniffTestPacketConn{delay: time.Second, closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		var metadata adapter.InboundContext
		packets, err := sniffPacketConnection(ctx, &metadata, &R.RuleActionSniff{Timeout: time.Second}, conn, nil, nil)
		releaseSniffPackets(packets)
		done <- err
	}()
	time.AfterFunc(10*time.Millisecond, cancel)
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancellation left a blocked reader")
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("business cancellation did not close connection")
	}
}
