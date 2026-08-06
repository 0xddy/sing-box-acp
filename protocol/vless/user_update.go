package vless

import (
	"github.com/sagernet/sing-box/option"
)

// UpdateUsers swaps in an immutable VLESS authentication snapshot without
// closing the listener, then drops the connections in the hand-off window that
// the replacement no longer authorizes. The replacement is built and validated
// first, so a rejected user list never leaves a half-updated inbound behind.
//
// Publishing before closing is what makes the hand-off airtight: a handshake
// that registers after the store is rejected by its own authorization check,
// and one that registered before it is closed here. Connections the router has
// already handed to its trackers are outside this window and are closed by
// whoever owns the tracker.
func (h *Inbound) UpdateUsers(users []option.VLESSUser) error {
	replacement, err := h.authenticatorForUsers(users)
	if err != nil {
		return err
	}
	h.auth.Store(replacement)
	h.connections.closeMatching(func(it credential) bool {
		_, stillAuthorized := replacement.authorized[it]
		return !stillAuthorized
	})
	return nil
}

// CloseUserSessions closes the connections of one user that are still inside
// the hand-off window, and reports how many it selected.
//
// An external tracker can only close connections the router already handed to
// it, and it cannot tell a connection authenticated before a kick from one
// authenticated after it. This entry point removes that ambiguity: everything
// it closes authenticated before the kick, so whatever reaches the tracker
// afterwards is genuinely new and may be admitted.
func (h *Inbound) CloseUserSessions(userID string) int {
	return h.connections.closeMatching(func(it credential) bool {
		return it.Name == userID
	})
}
