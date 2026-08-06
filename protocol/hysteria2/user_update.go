package hysteria2

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

var (
	_ adapter.UpdatableInbound[option.Hysteria2User] = (*Inbound)(nil)
	_ adapter.UserSessionCloser                      = (*Inbound)(nil)
)

// UpdateUsers atomically replaces the authentication table. The sing-quic
// service closes only sessions whose user identity or credential fingerprint
// is absent from the replacement.
func (h *Inbound) UpdateUsers(users []option.Hysteria2User) error {
	passwords := make([]string, 0, len(users))
	for _, user := range users {
		passwords = append(passwords, user.Password)
	}
	h.service.UpdateUsersWithSessionRevocation(userIdentities(users), passwords)
	return nil
}

// CloseUserSessions closes the authenticated QUIC transport sessions for one
// user while preserving sessions owned by every other user.
func (h *Inbound) CloseUserSessions(userID string) int {
	return h.service.CloseSessions(func(identity userIdentity) bool {
		return identity.Name == userID
	})
}
