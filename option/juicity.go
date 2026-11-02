package option

import "github.com/sagernet/sing/common/json/badoption"

type JuicityInboundOptions struct {
	ListenOptions
	Users             []JuicityUser      `json:"users,omitempty"`
	CongestionControl string             `json:"congestion_control,omitempty" enum:"bbr,cubic,new_reno"`
	AuthTimeout       badoption.Duration `json:"auth_timeout,omitempty"`
	InboundTLSOptionsContainer
	QUICOptions
}

type JuicityUser struct {
	Name     string `json:"name,omitempty"`
	UUID     string `json:"uuid"`
	Password string `json:"password"`
}

type JuicityOutboundOptions struct {
	DialerOptions
	ServerOptions
	UUID                  string      `json:"uuid"`
	Password              string      `json:"password"`
	CongestionControl     string      `json:"congestion_control,omitempty" enum:"bbr,cubic,new_reno"`
	UDPMode               string      `json:"udp_mode,omitempty" enum:"auto,stream,underlay"`
	PinnedCertChainSHA256 string      `json:"pinned_certchain_sha256,omitempty"`
	Network               NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	QUICOptions
}
