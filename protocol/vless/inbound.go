package vless

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.VLESSInboundOptions](registry, C.TypeVLESS, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	ctx         context.Context
	router      adapter.ConnectionRouterEx
	logger      logger.ContextLogger
	listener    *listener.Listener
	auth        atomic.Pointer[authenticator]
	connections connectionRegistry
	tlsConfig   tls.ServerConfig
	transport   adapter.V2RayServerTransport
}

// userIdentity is the identity carried on an authenticated connection. Index is
// only a display fallback for unnamed users; Name and CredentialFingerprint are
// what identify the user, so the identity survives a reordered user list and
// changes as soon as the authentication parameters are rotated.
type userIdentity struct {
	Index                 int
	Name                  string
	CredentialFingerprint [sha256.Size]byte
}

// credential is the order-independent part of an identity, used to decide
// whether an authenticated connection is still authorized.
type credential struct {
	Name                  string
	CredentialFingerprint [sha256.Size]byte
}

func (i userIdentity) credential() credential {
	return credential{Name: i.Name, CredentialFingerprint: i.CredentialFingerprint}
}

// String keeps the identity printable for the sing formatter, which panics on
// struct values it cannot stringify and is reached from transport error paths.
func (i userIdentity) String() string {
	if i.Name != "" {
		return i.Name
	}
	return F.ToString(i.Index)
}

// authenticator binds an immutable authentication snapshot to the credential
// set it authorizes so that both are replaced by a single atomic store.
type authenticator struct {
	service    *vless.Service[userIdentity]
	authorized map[credential]struct{}
}

func (a *authenticator) authorizes(identity userIdentity) bool {
	_, authorized := a.authorized[identity.credential()]
	return authorized
}

func userIdentities(users []option.VLESSUser) []userIdentity {
	return common.MapIndexed(users, func(index int, user option.VLESSUser) userIdentity {
		return userIdentity{
			Index:                 index,
			Name:                  user.Name,
			CredentialFingerprint: credentialFingerprint(normalizedUUID(user.UUID), user.Flow),
		}
	})
}

// normalizedUUID mirrors how sing-vmess derives the lookup key from a
// configured UUID, so duplicate detection and fingerprints agree with the
// authentication table even when two configurations spell the same UUID
// differently.
func normalizedUUID(rawUUID string) [16]byte {
	userID, err := uuid.FromString(rawUUID)
	if err != nil {
		userID = uuid.NewV5(uuid.Nil, rawUUID)
	}
	return userID
}

// credentialFingerprint covers every parameter the VLESS handshake
// authenticates against. Flow is included because sing-vmess rejects a request
// whose flow does not match the configured one, so changing it invalidates the
// sessions established under the previous value.
func credentialFingerprint(userID [16]byte, flow string) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write(userID[:])
	digest.Write([]byte{0})
	digest.Write([]byte(flow))
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], digest.Sum(nil))
	return fingerprint
}

// connectionRegistry covers the hand-off window: a connection is registered
// once it is authenticated and unregistered once RouteConnectionEx returns.
// Inside that window the router has already passed the connection to its
// trackers (it does so before starting the forwarding goroutines), so an
// external tracker owns every connection the registry drops. Nothing owns a
// connection before that point, and the window is long enough to matter because
// routing sniffs the stream first, waiting on payload the client decides when
// to send.
//
// The registry deliberately does not follow a connection for its whole life:
// once the router's trackers hold it, closing it twice from two places would
// only duplicate machinery that already exists outside sing-box.
type connectionRegistry struct {
	access      sync.Mutex
	connections map[*registeredConnection]struct{}
}

type registeredConnection struct {
	credential credential
	closer     io.Closer
}

func (r *connectionRegistry) add(identity userIdentity, closer io.Closer) *registeredConnection {
	registered := &registeredConnection{credential: identity.credential(), closer: closer}
	r.access.Lock()
	defer r.access.Unlock()
	if r.connections == nil {
		r.connections = make(map[*registeredConnection]struct{})
	}
	r.connections[registered] = struct{}{}
	return registered
}

func (r *connectionRegistry) remove(registered *registeredConnection) {
	r.access.Lock()
	defer r.access.Unlock()
	delete(r.connections, registered)
}

// closeMatching closes every registered connection whose credential matches.
// Closing happens outside the registry lock so a closer that unregisters
// synchronously cannot deadlock.
func (r *connectionRegistry) closeMatching(match func(credential) bool) int {
	r.access.Lock()
	revoked := make([]io.Closer, 0, len(r.connections))
	for registered := range r.connections {
		if match(registered.credential) {
			revoked = append(revoked, registered.closer)
			delete(r.connections, registered)
		}
	}
	r.access.Unlock()
	for _, closer := range revoked {
		_ = closer.Close()
	}
	return len(revoked)
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.VLESSInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeVLESS, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
	}
	var err error
	inbound.router, err = mux.NewRouterWithOptions(inbound.router, logger, common.PtrValueOrDefault(options.Multiplex))
	if err != nil {
		return nil, err
	}
	initialAuth, err := inbound.authenticatorForUsers(options.Users)
	if err != nil {
		return nil, err
	}
	inbound.auth.Store(initialAuth)
	if options.TLS != nil {
		inbound.tlsConfig, err = tls.NewServerWithOptions(tls.ServerOptions{
			Context: ctx,
			Logger:  logger,
			Options: common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: common.PtrValueOrDefault(options.Transport).Type == "" &&
				!common.PtrValueOrDefault(options.Multiplex).Enabled &&
				common.All(options.Users, func(it option.VLESSUser) bool {
					return it.Flow == ""
				}),
		})
		if err != nil {
			return nil, err
		}
	}
	if options.Transport != nil {
		inbound.transport, err = v2ray.NewServerTransport(ctx, logger, common.PtrValueOrDefault(options.Transport), inbound.tlsConfig, (*inboundTransportHandler)(inbound))
		if err != nil {
			return nil, E.Cause(err, "create server transport: ", options.Transport.Type)
		}
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
	}
	if h.transport == nil {
		return h.listener.Start()
	}
	if common.Contains(h.transport.Network(), N.NetworkTCP) {
		tcpListener, err := h.listener.ListenTCP()
		if err != nil {
			return err
		}
		go func() {
			sErr := h.transport.Serve(tcpListener)
			if sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	if common.Contains(h.transport.Network(), N.NetworkUDP) {
		udpConn, err := h.listener.ListenUDP()
		if err != nil {
			return err
		}
		go func() {
			sErr := h.transport.ServePacket(udpConn)
			if sErr != nil && !E.IsClosed(sErr) {
				h.logger.Error("transport serve error: ", sErr)
			}
		}()
	}
	return nil
}

func (h *Inbound) Close() error {
	var service *vless.Service[userIdentity]
	if current := h.auth.Load(); current != nil {
		service = current.service
	}
	return common.Close(
		service,
		h.listener,
		h.tlsConfig,
		h.transport,
	)
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil && h.transport == nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	current := h.auth.Load()
	if current == nil {
		N.CloseOnHandshakeFailure(conn, onClose, os.ErrClosed)
		return
	}
	err := current.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

// authenticatorForUsers builds a complete replacement snapshot before anything
// is published, so a rejected user list leaves the running authentication table
// untouched. Duplicate UUIDs are rejected because sing-vmess would silently let
// the last one win, leaving the shadowed user authorized here but unreachable
// there.
func (h *Inbound) authenticatorForUsers(users []option.VLESSUser) (*authenticator, error) {
	identities := userIdentities(users)
	authorized := make(map[credential]struct{}, len(identities))
	seen := make(map[[16]byte]string, len(users))
	for index, user := range users {
		userID := normalizedUUID(user.UUID)
		if owner, duplicate := seen[userID]; duplicate {
			return nil, E.New("duplicate UUID: ", user.UUID, ", already used by ", owner)
		}
		seen[userID] = identities[index].String()
		authorized[identities[index].credential()] = struct{}{}
	}
	service := vless.NewService[userIdentity](
		h.logger,
		adapter.NewUpstreamContextHandler(h.newConnectionEx, h.newPacketConnectionEx),
	)
	service.UpdateUsers(identities, common.Map(users, func(it option.VLESSUser) string {
		return it.UUID
	}), common.Map(users, func(it option.VLESSUser) string {
		return it.Flow
	}))
	return &authenticator{service: service, authorized: authorized}, nil
}

// authorizeConnection resolves the identity of a freshly authenticated
// connection, registers it, and only then checks it against the current
// snapshot. The snapshot is captured before the VLESS header is read and a
// client decides when to send that header, so the check is what stops a
// credential revoked mid-handshake. Registering first is what closes the
// remaining window: an update that publishes after the registration finds the
// connection in the registry, and one that published before it is caught by the
// check, so there is no point at which an authenticated connection is invisible
// to revocation.
//
// Callers must unregister the returned connection once they are done with it.
func (h *Inbound) authorizeConnection(ctx context.Context, closer io.Closer) (userIdentity, *registeredConnection, error) {
	identity, loaded := auth.UserFromContext[userIdentity](ctx)
	if !loaded {
		return userIdentity{}, nil, os.ErrInvalid
	}
	registered := h.connections.add(identity, closer)
	current := h.auth.Load()
	if current == nil || !current.authorizes(identity) {
		h.connections.remove(registered)
		return userIdentity{}, nil, os.ErrPermission
	}
	return identity, registered, nil
}

func (h *Inbound) newConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIdentity, registered, err := h.authorizeConnection(ctx, conn)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	defer h.connections.remove(registered)
	user := userIdentity.Name
	if user == "" {
		user = F.ToString(userIdentity.Index)
	} else {
		metadata.User = user
	}
	h.logger.DebugContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) newPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	userIdentity, registered, err := h.authorizeConnection(ctx, conn)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	defer h.connections.remove(registered)
	user := userIdentity.Name
	if user == "" {
		user = F.ToString(userIdentity.Index)
	} else {
		metadata.User = user
	}
	if metadata.Destination.Fqdn == packetaddr.SeqPacketMagicAddress {
		metadata.Destination = M.Socksaddr{}
		conn = packetaddr.NewConn(bufio.NewNetPacketConn(conn), metadata.Destination)
		h.logger.DebugContext(ctx, "[", user, "] inbound packet addr connection")
	} else {
		h.logger.DebugContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

var _ adapter.V2RayServerTransportHandler = (*inboundTransportHandler)(nil)

type inboundTransportHandler Inbound

func (h *inboundTransportHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Source = source
	metadata.Destination = destination
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	h.logger.DebugContext(ctx, "inbound connection from ", metadata.Source)
	(*Inbound)(h).NewConnection(ctx, conn, metadata, onClose)
}
