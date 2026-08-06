package vless

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

var _ adapter.UpdatableInbound[option.VLESSUser] = (*Inbound)(nil)

// UpdateUsers swaps in an immutable VLESS authentication snapshot without
// closing the listener. Existing handshakes retain the previous snapshot while
// new handshakes immediately use the replacement.
func (h *Inbound) UpdateUsers(users []option.VLESSUser) error {
	h.service.Store(h.serviceForUsers(users))
	return nil
}
