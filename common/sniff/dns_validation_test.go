package sniff

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestDNSResponseCannotCompleteQuerySniff(t *testing.T) {
	// A valid response with one question and no answers used to return nil
	// without identifying a protocol, falsely completing PeekPacket.
	packet := []byte{0, 1, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	var metadata adapter.InboundContext
	if err := DomainNameQuery(context.Background(), &metadata, packet); err == nil || metadata.Protocol != "" {
		t.Fatalf("response accepted as query: err=%v protocol=%q", err, metadata.Protocol)
	}
}
