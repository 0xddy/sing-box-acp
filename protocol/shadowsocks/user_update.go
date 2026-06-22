package shadowsocks

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

var _ adapter.UpdatableShadowsocksInbound = (*MultiInbound)(nil)

// UpdateUsersByOptions replaces Shadowsocks users in-place without closing the
// listener and keeps the full option snapshot for later hot updates.
func (h *MultiInbound) UpdateUsersByOptions(users []option.ShadowsocksUser) error {
	if err := h.service.UpdateUsersWithPasswords(common.MapIndexed(users, func(index int, _ option.ShadowsocksUser) int {
		return index
	}), common.Map(users, func(user option.ShadowsocksUser) string {
		return user.Password
	})); err != nil {
		return err
	}
	h.users = users
	return nil
}
