package vless

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

var _ adapter.UpdatableInbound[option.VLESSUser] = (*Inbound)(nil)

// UpdateUsers replaces VLESS users in-place without closing the listener.
func (h *Inbound) UpdateUsers(users []option.VLESSUser) error {
	h.users = users
	h.service.UpdateUsers(common.MapIndexed(h.users, func(index int, _ option.VLESSUser) int {
		return index
	}), common.Map(h.users, func(it option.VLESSUser) string {
		return it.UUID
	}), common.Map(h.users, func(it option.VLESSUser) string {
		return it.Flow
	}))
	return nil
}
