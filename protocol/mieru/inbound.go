package mieru

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	api "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/server"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/varbin"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"google.golang.org/protobuf/proto"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.MieruInboundOptions](registry, C.TypeMieru, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx     context.Context
	router  adapter.Router
	logger  log.ContextLogger
	service server.ManagedServer
	listen  option.ListenOptions
	workers sync.WaitGroup
}

type listenFactory struct{ listener *listener.Listener }

func (f listenFactory) Listen(context.Context, string, string) (net.Listener, error) {
	return f.listener.ListenTCP()
}
func (f listenFactory) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return f.listener.ListenUDP()
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, o option.MieruInboundOptions) (adapter.Inbound, error) {
	transport, pattern, err := settings(o.MieruOptions)
	if err != nil {
		return nil, err
	}
	f := listenFactory{listener.New(listener.Options{Context: ctx, Logger: logger, Listen: o.ListenOptions})}
	s := server.NewManagedServer()
	config := &pb.ServerConfig{
		ListenIPAddress:  proto.String(o.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1})).String()),
		Users:            credentials(o.Users),
		Mtu:              proto.Int32(int32(o.MTU)),
		TrafficPattern:   pattern,
		PortBindings:     []*pb.PortBinding{{Protocol: transport.Enum(), Port: proto.Int32(int32(o.ListenPort))}},
		AdvancedSettings: &pb.ServerAdvancedSettings{UserHintIsMandatory: proto.Bool(o.UserHintIsMandatory)},
	}
	if err = s.Store(&server.ServerConfig{Config: config, StreamListenerFactory: f, PacketListenerFactory: f}); err != nil {
		return nil, err
	}
	return &Inbound{Adapter: inbound.NewAdapter(C.TypeMieru, tag), ctx: ctx, router: router, logger: logger, service: s, listen: o.ListenOptions}, nil
}

func ValidateUsers(users []option.MieruUser) error { return server.ValidateUsers(credentials(users)) }
func (h *Inbound) UpdateUsers(users []option.MieruUser) error {
	return h.service.UpdateUsers(credentials(users))
}
func (h *Inbound) CloseUserSessions(name string) int { return h.service.CloseUserSessions(name) }

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := h.service.Start(); err != nil {
		return err
	}
	h.workers.Add(1)
	go h.acceptLoop()
	scope.Add(func() error {
		err := h.service.Stop()
		h.workers.Wait()
		return err
	})
	return nil
}

func (h *Inbound) acceptLoop() {
	defer h.workers.Done()
	for {
		conn, err := h.service.AcceptSession()
		if err != nil {
			return
		}
		h.workers.Add(1)
		go func() {
			defer h.workers.Done()
			if err := h.route(conn); err != nil {
				conn.Close()
				h.logger.Debug("mieru session: ", err)
			}
		}()
	}
}

func (h *Inbound) route(conn net.Conn) error {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	req, err := socks5.ReadRequest(varbin.StubReader(conn))
	if err != nil {
		return err
	}
	conn.SetReadDeadline(time.Time{})
	user, ok := conn.(api.UserContext)
	if !ok || user.UserName() == "" {
		return fmt.Errorf("missing authenticated user")
	}
	ctx := log.ContextWithNewID(h.ctx)
	metadata := adapter.InboundContext{
		Inbound: h.Tag(), InboundType: h.Type(), InboundDetour: h.listen.Detour,
		Source:            M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap(),
		OriginDestination: M.SocksaddrFromNet(conn.LocalAddr()).Unwrap(),
		Destination:       req.Destination, User: user.UserName(),
		UDPDisableDomainUnmapping: h.listen.UDPDisableDomainUnmapping,
	}
	switch req.Command {
	case socks5.CommandConnect:
		h.router.RouteConnectionEx(ctx, socks.NewLazyConn(conn, socks5.Version), metadata, nil)
	case socks5.CommandUDPAssociate:
		// The client waits for association success before sending the first target.
		if err := socks5.WriteResponse(conn, socks5.Response{ReplyCode: socks5.ReplyCodeSuccess}); err != nil {
			return err
		}
		timeout := time.Duration(h.listen.UDPTimeout)
		if timeout == 0 {
			timeout = C.UDPTimeout
		}
		return h.routeAssociation(ctx, newPacketConn(conn), metadata, timeout)
	default:
		_ = socks5.WriteResponse(conn, socks5.Response{ReplyCode: socks5.ReplyCodeUnsupported})
		return fmt.Errorf("unsupported SOCKS command %d", req.Command)
	}
	return nil
}
