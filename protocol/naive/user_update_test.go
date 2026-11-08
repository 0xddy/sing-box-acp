package naive

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing/common/auth"
)

func TestRevokeBeforeTransportHandoff(t *testing.T) {
	users, err := authenticationFor([]auth.User{{Username: "a", Password: "one"}, {Username: "b", Password: "one"}})
	if err != nil {
		t.Fatal(err)
	}
	n := &Inbound{users: users, flows: make(map[*userFlow]userIdentity)}
	first, ok := n.beginFlow(context.Background(), "a", "one")
	if !ok || first == nil {
		t.Fatal("authentication failed")
	}
	other, _ := n.beginFlow(context.Background(), "b", "one")
	defer other.Close()
	if got := n.CloseUserSessions("a"); got != 1 {
		t.Fatal(got)
	}
	left, right := net.Pipe()
	defer right.Close()
	if first.attach(left) {
		t.Fatal("revoked handshake reached router")
	}
	if other.ctx.Err() != nil {
		t.Fatal("different user revoked")
	}
	next, _ := n.beginFlow(context.Background(), "a", "one")
	if next == nil || next.ctx.Err() != nil {
		t.Fatal("kick incorrectly disabled account")
	}
	defer next.Close()
	if err = n.UpdateUsers([]auth.User{{Username: "a", Password: "two"}, {Username: "b", Password: "one"}}); err != nil {
		t.Fatal(err)
	}
	if next.ctx.Err() == nil {
		t.Fatal("changed credential not revoked")
	}
	if _, ok = n.beginFlow(context.Background(), "a", "one"); ok {
		t.Fatal("old credential accepted")
	}
	if err = n.UpdateUsers([]auth.User{{Username: "a", Password: "two"}, {Username: "a", Password: "three"}}); err == nil {
		t.Fatal("duplicate accepted")
	}
	valid, ok := n.beginFlow(context.Background(), "a", "two")
	if !ok {
		t.Fatal("failed update mutated users")
	}
	defer valid.Close()
	if err = n.UpdateUsers(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok = n.beginFlow(context.Background(), "a", "two"); ok {
		t.Fatal("empty table permits authentication")
	}
}

func TestNaiveAdmissionLimitsAndRelease(t *testing.T) {
	users, _ := authenticationFor([]auth.User{{Username: "a", Password: "one"}})
	n := &Inbound{users: users, flows: make(map[*userFlow]userIdentity)}
	var releases []func()
	for i := 0; i < MaxTransportConnections; i++ {
		release, ok := n.AcquireTransport()
		if !ok {
			t.Fatalf("transport rejected below limit: %d", i)
		}
		releases = append(releases, release)
	}
	if _, ok := n.AcquireTransport(); ok {
		t.Fatal("transport limit exceeded")
	}
	for _, release := range releases {
		release()
		release()
	}
	if n.transportCount != 0 {
		t.Fatal("transport release was not idempotent")
	}
	for i := 0; i < maxAuthenticatedFlows; i++ {
		flow, ok := n.beginFlow(context.Background(), "a", "one")
		if !ok || flow == nil {
			t.Fatalf("flow rejected below limit: %d", i)
		}
		defer flow.Close()
	}
	if flow, ok := n.beginFlow(context.Background(), "a", "one"); !ok || flow != nil {
		t.Fatal("flow limit did not preserve authenticated rejection")
	}
	for flow := range n.flows {
		n.endFlow(flow)
		break
	}
	flow, ok := n.beginFlow(context.Background(), "a", "one")
	if !ok || flow == nil {
		t.Fatal("released flow slot was not reusable")
	}
	defer flow.Close()
}
