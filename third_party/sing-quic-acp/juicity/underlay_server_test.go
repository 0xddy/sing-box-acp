package juicity

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestUnderlayPendingBudgetAndExpiry(t *testing.T) {
	ctx := t.Context()
	service := &Service{ctx: ctx, options: ServiceOptions{UDPTimeout: time.Minute}}
	owner := &serverSession{ctx: ctx, Service: service}
	hub := newUnderlayServer(service, nil)
	wire := make([]byte, 2048)
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	for i := 0; i < 2*maxPending; i++ {
		binary.BigEndian.PutUint32(wire[28:32], uint32(i))
		hub.receive(wire, src, true)
	}
	if len(hub.early) > maxPending || hub.earlyBytes > maxPendingBytes || len(hub.peers) != 0 {
		t.Fatal("unauthenticated packets exceeded queue budget")
	}
	var reg registration
	reg.Salt[30] = 255
	if !hub.register(owner, reg) {
		t.Fatal("registration rejected")
	}
	if hub.register(owner, reg) {
		t.Fatal("duplicate grant accepted")
	}
	hub.prune(time.Now().Add(defaultAuthTimeout + time.Second))
	if len(hub.early) != 0 || hub.earlyBytes != 0 || len(hub.grants) != 0 {
		t.Fatal("expired entries retained")
	}
	ctx2, cancel := context.WithCancel(ctx)
	cancel()
	if hub.register(&serverSession{ctx: ctx2}, reg) {
		t.Fatal("revoked session registered a key")
	}
}

func TestUnderlayReplayBudget(t *testing.T) {
	var seen saltWindow
	var s salt
	for i := 0; i < saltsPerKey; i++ {
		binary.BigEndian.PutUint32(s[28:], uint32(i))
		if !seen.accept(s) {
			t.Fatalf("new salt %d rejected", i)
		}
	}
	if seen.accept(salt{}) {
		t.Fatal("oldest replay accepted")
	}
	binary.BigEndian.PutUint32(s[28:], saltsPerKey)
	if seen.accept(s) {
		t.Fatal("saturated key exceeded its budget")
	}
}
