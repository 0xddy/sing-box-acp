package hysteria2

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
)

type afterFuncTrackingContext struct {
	context.Context
	active atomic.Int32
}

// Hide the wrapped cancel context so child retention is observable through AfterFunc.
func (c *afterFuncTrackingContext) Value(any) any {
	return nil
}

func (c *afterFuncTrackingContext) AfterFunc(f func()) func() bool {
	c.active.Add(1)
	stop := context.AfterFunc(c.Context, func() {
		c.active.Add(-1)
		f()
	})
	return func() bool {
		if !stop() {
			return false
		}
		c.active.Add(-1)
		return true
	}
}

func TestInboundCloseCancelsExistingServiceSessions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	inbound := &Inbound{serviceCancel: cancel}

	inbound.cancelService()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("inbound close did not cancel the service context")
	}
}

func TestNewInboundRealmValidationDoesNotRetainServiceContext(t *testing.T) {
	parentCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &afterFuncTrackingContext{Context: parentCtx}

	_, err := NewInbound(ctx, nil, log.NewNOPFactory().NewLogger("test"), "test", option.Hysteria2InboundOptions{
		ListenOptions: option.ListenOptions{
			Listen: common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
		},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:  true,
				Insecure: true,
			},
		},
		Realm: &option.Hysteria2InboundRealm{
			Hysteria2Realm: option.Hysteria2Realm{IPVersion: 6},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "realm.ip_version 6 conflicts with listen address") {
		t.Fatalf("NewInbound() error = %v, want Realm IP version conflict", err)
	}
	if active := ctx.active.Load(); active != 0 {
		t.Fatalf("active service context registrations = %d, want 0 after constructor failure", active)
	}
}

func TestUserIdentitiesAreStableSnapshots(t *testing.T) {
	users := []option.Hysteria2User{
		{Name: "user-1", Password: "password-1"},
		{Name: "user-2", Password: "password-2"},
	}
	identities := userIdentities(users)
	users[1].Name = "changed"
	users[1].Password = "changed-password"

	if len(identities) != 2 {
		t.Fatalf("identity count = %d, want 2", len(identities))
	}
	if identities[1].Name != "user-2" || identities[1].CredentialFingerprint != sha256.Sum256([]byte("password-2")) {
		t.Fatalf("identity = %+v, want stable name and credential fingerprint", identities[1])
	}
}

func TestUserIdentityDoesNotDependOnListOrder(t *testing.T) {
	first := userIdentities([]option.Hysteria2User{
		{Name: "user-1", Password: "password-1"},
		{Name: "user-2", Password: "password-2"},
	})
	reordered := userIdentities([]option.Hysteria2User{
		{Name: "user-2", Password: "password-2"},
		{Name: "user-1", Password: "password-1"},
	})

	if first[0] != reordered[1] || first[1] != reordered[0] {
		t.Fatalf("reordering changed identities: first=%+v reordered=%+v", first, reordered)
	}
}

func TestCredentialChangeCreatesNewUserIdentity(t *testing.T) {
	original := userIdentities([]option.Hysteria2User{{Name: "user-1", Password: "old-password"}})
	updated := userIdentities([]option.Hysteria2User{{Name: "user-1", Password: "new-password"}})

	if original[0] == updated[0] {
		t.Fatal("credential change retained the previous authenticated identity")
	}
}
