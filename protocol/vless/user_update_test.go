package vless

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestUserIdentitiesAreStableSnapshots(t *testing.T) {
	users := []option.VLESSUser{
		{Name: "user-1"},
		{Name: "user-2"},
	}
	identities := userIdentities(users)
	users[1].Name = "changed"

	if len(identities) != 2 {
		t.Fatalf("identity count = %d, want 2", len(identities))
	}
	if identities[1].Index != 1 || identities[1].Name != "user-2" {
		t.Fatalf("identity = %+v, want stable index and name", identities[1])
	}
}
