package route

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	maxSniffPackets     = 8
	maxSniffPacketBytes = 64 * 1024
)

// Only newly read packets are returned: matchRule already owns the cached ones.
// A sniff budget failure is nonfatal, and every read payload remains replayable.
func sniffPacketConnection(ctx context.Context, metadata *adapter.InboundContext, action *R.RuleActionSniff, conn N.PacketConn, cached []*N.PacketBuffer, sniffers []sniff.PacketSniffer) (packets []*N.PacketBuffer, fatalErr error) {
	timeout := action.Timeout
	if timeout <= 0 {
		timeout = C.ReadPayloadTimeout
	}
	deadline := time.Now().Add(timeout)
	parseCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	metadata.SniffContext = nil
	metadata.SniffDestination = M.Socksaddr{}
	metadata.SniffDomain = ""
	metadata.SniffECHPresent = false
	candidate := *metadata
	var target M.Socksaddr
	count, size := 0, 0
	var sniffErr error
	defer func() {
		metadata.SnifferNames = action.SnifferNames
		metadata.SniffError = sniffErr
		metadata.SniffContext = nil
		if fatalErr != nil {
			N.ReleaseMultiPacketBuffer(packets)
			packets = nil
		}
	}()
	inspect := func(packet *N.PacketBuffer) bool {
		if err := parseCtx.Err(); err != nil {
			sniffErr = err
			return false
		}
		count++
		size += packet.Buffer.Len()
		if count > maxSniffPackets || size > maxSniffPacketBytes || !packet.Destination.IsValid() {
			sniffErr = os.ErrInvalid
			return false
		}
		if count == 1 {
			target = packet.Destination
			if target != metadata.Destination {
				// Reverse-mapped or transport-domain hints belong to the
				// declared target, not an unrelated per-packet destination.
				candidate.Domain, candidate.Client = "", ""
			}
		} else if packet.Destination != target {
			sniffErr = os.ErrInvalid
			return false
		}
		if candidate.SniffContext != nil {
			sniffErr = sniff.PeekPacket(parseCtx, &candidate, packet.Buffer.Bytes(), sniff.QUICClientHello)
		} else {
			sniffErr = sniff.PeekPacket(parseCtx, &candidate, packet.Buffer.Bytes(), sniffers...)
		}
		if sniffErr == nil {
			if err := parseCtx.Err(); err != nil {
				sniffErr = err
				return false
			}
			metadata.Protocol, metadata.Domain, metadata.Client = candidate.Protocol, candidate.Domain, candidate.Client
			metadata.SniffDomain = candidate.SniffDomain
			metadata.SniffECHPresent = candidate.SniffECHPresent
			metadata.SniffDestination = target
		}
		return errors.Is(sniffErr, sniff.ErrNeedMoreData)
	}
	for _, packet := range cached {
		if !inspect(packet) {
			return packets, ctx.Err()
		}
	}
	// Unsupported deadlines cannot safely wait without a detached reader or
	// closing the business connection. Continue routing the cached payload.
	if err := conn.SetReadDeadline(deadline); err != nil {
		sniffErr = err
		return packets, ctx.Err()
	}
	defer conn.SetReadDeadline(time.Time{})
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	for count < maxSniffPackets && size < maxSniffPacketBytes {
		if err := parseCtx.Err(); err != nil {
			sniffErr = err
			return packets, ctx.Err()
		}
		buffer := buf.NewPacket()
		destination, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			sniffErr = err
			if ctx.Err() != nil {
				return packets, ctx.Err()
			}
			if E.IsTimeout(err) {
				return packets, nil
			}
			return packets, err
		}
		packet := N.NewPacketBuffer()
		packet.Buffer, packet.Destination = buffer, destination
		packets = append(packets, packet)
		if !inspect(packet) {
			return packets, ctx.Err()
		}
	}
	sniffErr = os.ErrInvalid
	return packets, ctx.Err()
}
