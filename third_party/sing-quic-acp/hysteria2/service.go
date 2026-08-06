package hysteria2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ServiceOptions struct {
	Context               context.Context
	Logger                logger.Logger
	BrutalDebug           bool
	SendBPS               uint64
	ReceiveBPS            uint64
	IgnoreClientBandwidth bool
	SalamanderPassword    string
	TLSConfig             aTLS.ServerConfig
	UDPDisabled           bool
	UDPTimeout            time.Duration
	Handler               ServerHandler
	MasqueradeHandler     http.Handler
}

type ServerHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

var errUserSessionRevoked = errors.New("user session revoked")

type userSnapshot[U comparable] struct {
	byPassword map[string]U
	identities map[U]struct{}
}

func newUserSnapshot[U comparable](userList []U, passwordList []string) *userSnapshot[U] {
	byPassword := make(map[string]U, len(userList))
	for i, user := range userList {
		byPassword[passwordList[i]] = user
	}
	identities := make(map[U]struct{}, len(byPassword))
	for _, user := range byPassword {
		identities[user] = struct{}{}
	}
	return &userSnapshot[U]{
		byPassword: byPassword,
		identities: identities,
	}
}

type authenticatedUser[U comparable] struct {
	identity U
}

type managedSession[U comparable] interface {
	authenticatedIdentity() (U, bool)
	closeWithError(err error) bool
}

type Service[U comparable] struct {
	ctx                   context.Context
	logger                logger.Logger
	brutalDebug           bool
	sendBPS               uint64
	receiveBPS            uint64
	ignoreClientBandwidth bool
	salamanderPassword    string
	tlsConfig             aTLS.ServerConfig
	quicConfig            *quic.Config
	users                 atomic.Pointer[userSnapshot[U]]
	udpDisabled           bool
	udpTimeout            time.Duration
	handler               ServerHandler
	masqueradeHandler     http.Handler
	quicListener          io.Closer
	sessionAccess         sync.Mutex
	sessions              map[managedSession[U]]struct{}
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                !options.UDPDisabled,
		MaxIncomingStreams:             1 << 60,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
		DisablePathManager:             true,
	}
	if options.MasqueradeHandler == nil {
		options.MasqueradeHandler = http.NotFoundHandler()
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	service := &Service[U]{
		ctx:                   options.Context,
		logger:                options.Logger,
		brutalDebug:           options.BrutalDebug,
		sendBPS:               options.SendBPS,
		receiveBPS:            options.ReceiveBPS,
		ignoreClientBandwidth: options.IgnoreClientBandwidth,
		salamanderPassword:    options.SalamanderPassword,
		tlsConfig:             options.TLSConfig,
		quicConfig:            quicConfig,
		udpDisabled:           options.UDPDisabled,
		udpTimeout:            options.UDPTimeout,
		handler:               options.Handler,
		masqueradeHandler:     options.MasqueradeHandler,
		sessions:              make(map[managedSession[U]]struct{}),
	}
	service.users.Store(newUserSnapshot([]U(nil), nil))
	return service, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	s.users.Store(newUserSnapshot(userList, passwordList))
}

// UpdateUsersWithSessionRevocation atomically replaces the authentication
// table and closes sessions whose authenticated identity is absent from the
// replacement. Callers can include a credential generation in U to revoke a
// session when one user's password changes without disturbing other users.
func (s *Service[U]) UpdateUsersWithSessionRevocation(userList []U, passwordList []string) int {
	snapshot := newUserSnapshot(userList, passwordList)
	s.users.Store(snapshot)
	return s.closeSessions(func(user U) bool {
		_, authorized := snapshot.identities[user]
		return !authorized
	})
}

// CloseSessions closes authenticated QUIC sessions matching one caller-owned
// identity predicate. It returns the number of sessions selected for close.
func (s *Service[U]) CloseSessions(match func(U) bool) int {
	if match == nil {
		return 0
	}
	return s.closeSessions(match)
}

func (s *Service[U]) closeSessions(match func(U) bool) int {
	matched := s.matchingSessions(match)
	closed := 0
	for _, session := range matched {
		if session.closeWithError(errUserSessionRevoked) {
			closed++
		}
	}
	return closed
}

func (s *Service[U]) matchingSessions(match func(U) bool) []managedSession[U] {
	s.sessionAccess.Lock()
	candidates := make([]struct {
		session  managedSession[U]
		identity U
	}, 0, len(s.sessions))
	for session := range s.sessions {
		identity, authenticated := session.authenticatedIdentity()
		if authenticated {
			candidates = append(candidates, struct {
				session  managedSession[U]
				identity U
			}{session: session, identity: identity})
		}
	}
	s.sessionAccess.Unlock()

	matched := make([]managedSession[U], 0, len(candidates))
	for _, candidate := range candidates {
		if match(candidate.identity) {
			matched = append(matched, candidate.session)
		}
	}
	return matched
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	if s.salamanderPassword != "" {
		conn = NewSalamanderConn(conn, []byte(s.salamanderPassword))
	}
	err := qtls.ConfigureHTTP3(s.tlsConfig)
	if err != nil {
		return err
	}
	listener, err := qtls.Listen(conn, s.tlsConfig, s.quicConfig)
	if err != nil {
		return err
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(
		s.quicListener,
	)
}

func (s *Service[U]) loopConnections(listener qtls.Listener) {
	for {
		connection, err := listener.Accept(s.ctx)
		if err != nil {
			if E.IsClosedOrCanceled(err) || errors.Is(err, quic.ErrServerClosed) {
				s.logger.Debug(E.Cause(err, "listener closed"))
			} else {
				s.logger.Error(E.Cause(err, "listener closed"))
			}
			return
		}
		go s.handleConnection(connection)
	}
}

func (s *Service[U]) handleConnection(connection *quic.Conn) {
	sessionCtx, sessionCancel := common.ContextWithCancelCause(s.ctx)
	session := &serverSession[U]{
		Service:    s,
		ctx:        sessionCtx,
		cancel:     sessionCancel,
		quicConn:   connection,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	defer sessionCancel(net.ErrClosed)
	s.sessionAccess.Lock()
	s.sessions[session] = struct{}{}
	s.sessionAccess.Unlock()
	defer func() {
		s.sessionAccess.Lock()
		delete(s.sessions, session)
		s.sessionAccess.Unlock()
	}()
	httpServer := http3.Server{
		Handler:          session,
		StreamDispatcher: session.dispatchStream,
	}
	_ = httpServer.ServeQUICConn(connection)
	_ = connection.CloseWithError(0, "")
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx               context.Context
	cancel            common.ContextCancelCauseFunc
	quicConn          *quic.Conn
	connAccess        sync.Mutex
	connDone          chan struct{}
	connErr           error
	authenticatedUser atomic.Pointer[authenticatedUser[U]]
	udpAccess         sync.RWMutex
	udpConnMap        map[uint32]*udpPacketConn
}

func (s *serverSession[U]) authenticatedIdentity() (U, bool) {
	authenticated := s.authenticatedUser.Load()
	if authenticated == nil {
		var zero U
		return zero, false
	}
	return authenticated.identity, true
}

func (s *serverSession[U]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		if s.authenticatedUser.Load() != nil {
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !s.udpDisabled,
				Rx:         s.receiveBPS,
				RxAuto:     s.receiveBPS == 0 && s.ignoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		request := protocol.AuthRequestFromHeader(r.Header)
		snapshot := s.users.Load()
		user, loaded := snapshot.byPassword[request.Auth]
		if !loaded {
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		}
		var rxAuto bool
		if s.receiveBPS > 0 && s.ignoreClientBandwidth && request.Rx == 0 {
			s.logger.Debug("process connection from ", r.RemoteAddr, ": BBR disabled by server")
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		} else if !(s.receiveBPS == 0 && s.ignoreClientBandwidth) && request.Rx > 0 {
			rx := request.Rx
			if s.sendBPS > 0 && rx > s.sendBPS {
				rx = s.sendBPS
			}
			s.quicConn.SetCongestionControl(hyCC.NewBrutalSender(rx, s.brutalDebug, s.logger))
		} else {
			timeFunc := ntp.TimeFuncFromContext(s.ctx)
			if timeFunc == nil {
				timeFunc = time.Now
			}
			s.quicConn.SetCongestionControl(congestion_meta2.NewBbrSender(
				congestion_meta2.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(s.quicConn.Config().InitialPacketSize),
				congestion.ByteCount(congestion_meta1.InitialCongestionWindow),
			))
			rxAuto = true
		}
		authenticated := &authenticatedUser[U]{identity: user}
		if !s.authenticatedUser.CompareAndSwap(nil, authenticated) {
			authenticated = s.authenticatedUser.Load()
		}
		currentSnapshot := s.users.Load()
		if currentSnapshot != snapshot {
			if _, authorized := currentSnapshot.identities[authenticated.identity]; !authorized {
				s.authenticatedUser.CompareAndSwap(authenticated, nil)
				s.closeWithError(errUserSessionRevoked)
				return
			}
		}
		protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
			UDPEnabled: !s.udpDisabled,
			Rx:         s.receiveBPS,
			RxAuto:     rxAuto,
		})
		w.WriteHeader(protocol.StatusAuthOK)
		if s.ctx.Done() != nil {
			go func() {
				select {
				case <-s.ctx.Done():
					s.closeWithError(s.ctx.Err())
				case <-s.connDone:
				}
			}()
		}
		if !s.udpDisabled {
			go s.loopMessages()
		}
	} else {
		s.masqueradeHandler.ServeHTTP(w, r)
	}
}

func (s *serverSession[U]) dispatchStream(frameType http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if s.authenticatedUser.Load() == nil || err != nil {
		return false, nil
	}
	if frameType != protocol.FrameTypeTCPRequest {
		return false, nil
	}
	_, err = quicvarint.Read(quicvarint.NewReader(stream))
	if err != nil {
		s.logger.Error(E.Cause(err, "seek frame type"))
		return true, nil
	}
	go func() {
		hErr := s.handleStream(stream)
		if hErr != nil {
			stream.CancelRead(0)
			stream.Close()
			s.logger.Error(E.Cause(hErr, "handle stream request"))
		}
	}()
	return true, nil
}

func (s *serverSession[U]) handleStream(stream *quic.Stream) error {
	destinationString, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		return E.New("read TCP request")
	}
	authenticated := s.authenticatedUser.Load()
	if authenticated == nil {
		return errUserSessionRevoked
	}
	s.handler.NewConnectionEx(auth.ContextWithUser(s.ctx, authenticated.identity), &serverConn{Stream: stream}, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), M.ParseSocksaddr(destinationString).Unwrap(), nil)
	return nil
}

func (s *serverSession[U]) closeWithError(err error) bool {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return false
	default:
		s.connErr = err
		close(s.connDone)
	}
	s.cancel(err)
	if E.IsClosedOrCanceled(err) || errors.Is(err, errUserSessionRevoked) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
	_ = s.quicConn.CloseWithError(0, "")
	return true
}

type serverConn struct {
	*quic.Stream
	responseWritten bool
}

func (c *serverConn) HandshakeFailure(err error) error {
	if c.responseWritten {
		return os.ErrInvalid
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(false, err.Error(), nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) HandshakeSuccess() error {
	if c.responseWritten {
		return nil
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(true, "", nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	if !c.responseWritten {
		c.responseWritten = true
		buffer := protocol.WriteTCPResponse(true, "", p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return 0, qtls.WrapError(err)
		}
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	err := c.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	c.Stream.SetWriteDeadline(time.Now())
	return err
}
