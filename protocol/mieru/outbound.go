package mieru

import (
	"context"
	"fmt"
	"net"

	"github.com/enfein/mieru/v3/apis/client"
	api "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MieruOutboundOptions](registry, C.TypeMieru, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	client client.Client
}

type endpointDialer struct{ N.Dialer }

func (d endpointDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
}
func (d endpointDialer) ListenPacket(ctx context.Context, _, _, remote string) (net.PacketConn, error) {
	return d.Dialer.ListenPacket(ctx, M.ParseSocksaddr(remote))
}

type endpointResolver struct {
	ctx     context.Context
	options *option.DomainResolveOptions
}

func (r endpointResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	options, err := dialer.NewDNSQueryOptions(r.ctx, r.options, false)
	if err != nil {
		return nil, err
	}
	addresses, err := service.FromContext[adapter.DNSRouter](r.ctx).Lookup(ctx, host, options)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, addr := range addresses {
		if network == "ip4" && !addr.Is4() || network == "ip6" && !addr.Is6() {
			continue
		}
		ips = append(ips, net.IP(addr.AsSlice()))
	}
	return ips, nil
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, o option.MieruOutboundOptions) (adapter.Outbound, error) {
	profile, err := clientProfile(o)
	if err != nil {
		return nil, err
	}
	d, err := dialer.New(ctx, o.DialerOptions, o.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	c := client.NewClient()
	err = c.Store(&client.ClientConfig{
		Profile: profile, Dialer: endpointDialer{d}, PacketDialer: endpointDialer{d},
		Resolver:  endpointResolver{ctx, o.DomainResolver},
		DNSConfig: &api.ClientDNSConfig{BypassDialerDNS: true},
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{outbound.NewAdapterWithDialerOptions(C.TypeMieru, tag, o.Network.Build(), o.DialerOptions), c}, nil
}
func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := o.client.Start(); err != nil {
		return err
	}
	scope.Add(o.client.Stop)
	return nil
}
func (o *Outbound) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return o.client.DialContext(ctx, model.NetAddrSpec{Net: "tcp", AddrSpec: model.AddrSpec{IP: dst.Addr.AsSlice(), FQDN: dst.Fqdn, Port: int(dst.Port)}})
	case N.NetworkUDP:
		c, err := o.ListenPacket(ctx, dst)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(c, dst), nil
	default:
		return nil, fmt.Errorf("unsupported network %q", network)
	}
}
func (o *Outbound) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	c, err := o.client.DialContext(ctx, model.NetAddrSpec{Net: "udp", AddrSpec: model.AddrSpec{IP: net.IPv4zero}})
	if err != nil {
		return nil, err
	}
	return addressedConn{newPacketConn(c)}, nil
}
