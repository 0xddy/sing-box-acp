package juicity

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	J "github.com/sagernet/sing-quic/juicity"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.JuicityOutboundOptions](registry, C.TypeJuicity, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	client *J.Client
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, o option.JuicityOutboundOptions) (adapter.Outbound, error) {
	id, pin, err := o.ClientCredentials()
	if err != nil {
		return nil, err
	}
	opts := *o.TLS
	opts.MinVersion = "1.3"
	opts.ALPN = []string{"h3"}
	if pin != nil {
		opts.Insecure = true // Verification is supplied by withChainPin.
	}
	cfg, err := tls.NewClient(ctx, logger, o.Server, opts)
	if err != nil {
		return nil, err
	}
	if pin != nil {
		cfg, err = withChainPin(cfg, pin)
		if err != nil {
			return nil, err
		}
	}
	d, err := dialer.New(ctx, o.DialerOptions, o.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	client, err := J.NewClient(J.ClientOptions{
		Context: ctx, Dialer: d, ServerAddress: o.ServerOptions.Build(), TLSConfig: cfg,
		QUICOptions: quicOptions(o.QUICOptions), CongestionControl: o.CongestionControl,
		User: J.User{UUID: id, Password: o.Password}, UDPMode: o.UDPMode,
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{outbound.NewAdapterWithDialerOptions(C.TypeJuicity, tag, o.Network.Build(), o.DialerOptions), client}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return h.client.DialConn(ctx, dst)
	case N.NetworkUDP:
		c, err := h.ListenPacket(ctx, dst)
		if err != nil {
			return nil, err
		}
		return bufio.NewBindPacketConn(c, dst), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	return h.client.ListenPacket(ctx, dst)
}

func (h *Outbound) InterfaceUpdated(context.Context) { h.client.Reset() }

func (h *Outbound) MultiplexEnabled() bool { return true }

func (h *Outbound) CloseIdleConnections() { h.client.CloseIdleConnections() }

func (h *Outbound) SetKeepIdleConnections(keep bool) { h.client.SetKeepIdleConnections(keep) }

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(h.client.Close)
	}
	return nil
}
