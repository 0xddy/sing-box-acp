package juicity

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	J "github.com/sagernet/sing-quic/juicity"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.JuicityInboundOptions](registry, C.TypeJuicity, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router   adapter.Router
	listener *listener.Listener
	tls      tls.ServerConfig
	service  *J.Service
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, o option.JuicityInboundOptions) (adapter.Inbound, error) {
	if o.TLS == nil || !o.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	opts := *o.TLS
	if err := validateTLS(opts.MinVersion, opts.MaxVersion, opts.ALPN); err != nil {
		return nil, err
	}
	opts.MinVersion = "1.3"
	opts.ALPN = []string{"h3"}
	cfg, err := tls.NewServer(ctx, logger, opts)
	if err != nil {
		return nil, err
	}
	h := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeJuicity, tag), router: router, tls: cfg,
		listener: listener.New(listener.Options{Context: ctx, Logger: logger, Listen: o.ListenOptions}),
	}
	h.service, err = J.NewService(J.ServiceOptions{
		Context: ctx, Logger: logger, TLSConfig: cfg, Handler: h,
		QUICOptions: quicOptions(o.QUICOptions), CongestionControl: o.CongestionControl,
		AuthTimeout: time.Duration(o.AuthTimeout), UDPTimeout: time.Duration(o.UDPTimeout),
	})
	if err != nil {
		return nil, err
	}
	if err = h.UpdateUsers(o.Users); err != nil {
		_ = h.service.Close()
		return nil, err
	}
	return h, nil
}

func parseUsers(users []option.JuicityUser) ([]J.User, error) {
	table := make([]J.User, 0, len(users))
	for i, u := range users {
		id, err := uuid.FromString(u.UUID)
		if err != nil {
			return nil, E.New("invalid uuid for user ", i)
		}
		table = append(table, J.User{Name: u.Name, UUID: id, Password: u.Password})
	}
	return table, nil
}

// ValidateUsers allows a caller to prepare all user changes before applying any of them.
func ValidateUsers(users []option.JuicityUser) error {
	table, err := parseUsers(users)
	if err != nil {
		return err
	}
	return J.ValidateUsers(table)
}

func (h *Inbound) UpdateUsers(users []option.JuicityUser) error {
	table, err := parseUsers(users)
	if err != nil {
		return err
	}
	return h.service.UpdateUsers(table)
}

func (h *Inbound) CloseUserSessions(name string) int { return h.service.CloseUserSessions(name) }

func (h *Inbound) UpdateTLSCertificate(certificate *stdtls.Certificate) error {
	return tls.UpdateCertificate(h.tls, certificate)
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := h.tls.Start(); err != nil {
		return err
	}
	scope.Add(h.tls.Close)
	conn, err := h.listener.ListenUDP()
	if err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	if err = h.service.Start(conn); err != nil {
		return err
	}
	scope.Add(h.service.Close)
	return nil
}

func (h *Inbound) metadata(ctx context.Context, src, dst M.Socksaddr) adapter.InboundContext {
	user, _ := auth.UserFromContext[string](ctx)
	return adapter.InboundContext{
		Inbound: h.Tag(), InboundType: h.Type(), Source: src, Destination: dst, User: user,
		InboundDetour: h.listener.ListenOptions().Detour, OriginDestination: h.listener.UDPAddr(),
	}
}

func (h *Inbound) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.router.RouteConnectionEx(log.ContextWithNewID(ctx), c, h.metadata(ctx, src, dst), onClose)
}

func (h *Inbound) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.router.RoutePacketConnectionEx(log.ContextWithNewID(ctx), c, h.metadata(ctx, src, dst), onClose)
}
