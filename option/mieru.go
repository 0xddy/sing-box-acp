package option

import "github.com/sagernet/sing/common/json/badoption"

type MieruOptions struct {
	Transport      string `json:"transport,omitempty" enum:"tcp,udp"`
	MTU            int    `json:"mtu,omitempty"`
	TrafficPattern string `json:"traffic_pattern,omitempty"`
}

type MieruInboundOptions struct {
	ListenOptions
	MieruOptions
	Users               []MieruUser `json:"users,omitempty"`
	UserHintIsMandatory bool        `json:"user_hint_is_mandatory,omitempty"`
}

type MieruUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type MieruOutboundOptions struct {
	DialerOptions
	ServerOptions
	MieruOptions
	ServerPorts   badoption.Listable[string] `json:"server_ports,omitempty"`
	Username      string                     `json:"username"`
	Password      string                     `json:"password"`
	Multiplexing  string                     `json:"multiplexing,omitempty" enum:"off,low,middle,high"`
	HandshakeMode string                     `json:"handshake_mode,omitempty" enum:"standard,no_wait"`
	Network       NetworkList                `json:"network,omitempty"`
}
