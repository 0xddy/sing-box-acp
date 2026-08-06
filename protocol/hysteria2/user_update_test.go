package hysteria2

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/sagernet/sing-box/option"
)

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
