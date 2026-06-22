package trojan

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

var _ adapter.UpdatableInbound[option.TrojanUser] = (*Inbound)(nil)

// UpdateUsers replaces Trojan users in-place without closing the listener.
func (h *Inbound) UpdateUsers(users []option.TrojanUser) error {
	h.users = users
	return h.service.UpdateUsers(common.MapIndexed(h.users, func(index int, _ option.TrojanUser) int {
		return index
	}), common.Map(h.users, func(it option.TrojanUser) string {
		return it.Password
	}))
}
