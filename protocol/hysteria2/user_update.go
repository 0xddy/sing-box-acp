package hysteria2

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

var _ adapter.UpdatableInbound[option.Hysteria2User] = (*Inbound)(nil)

// UpdateUsers replaces Hysteria2 users in-place without closing the listener.
func (h *Inbound) UpdateUsers(users []option.Hysteria2User) error {
	userList := make([]int, 0, len(users))
	userNameList := make([]string, 0, len(users))
	userPasswordList := make([]string, 0, len(users))
	for index, user := range users {
		userList = append(userList, index)
		userNameList = append(userNameList, user.Name)
		userPasswordList = append(userPasswordList, user.Password)
	}
	h.service.UpdateUsers(userList, userPasswordList)
	h.userNameList = userNameList
	return nil
}
