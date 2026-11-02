package juicity

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type ServiceOptions struct {
	Context                 context.Context
	TLSConfig               aTLS.ServerConfig
	Logger                  logger.Logger
	QUICOptions             qtls.QUICOptions
	CongestionControl       string
	AuthTimeout, UDPTimeout time.Duration
	Handler                 Handler
}

type Service struct {
	options ServiceOptions
	// The same lock serializes publishing a new table and admitting a session
	// authenticated against the previous one.
	mu        sync.Mutex
	users     atomic.Pointer[map[[16]byte]User]
	sessions  map[*serverSession]User
	transport *quic.Transport
	underlay  *underlayServer
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewService(o ServiceOptions) (*Service, error) {
	if o.Context == nil || o.TLSConfig == nil || o.Handler == nil {
		return nil, errors.New("Juicity service requires a context, TLS config and handler")
	}
	if o.Logger == nil {
		o.Logger = logger.NOP()
	}
	if err := validCongestion(o.CongestionControl); err != nil {
		return nil, err
	}
	if o.QUICOptions.MaxConcurrentStreams != 0 && o.QUICOptions.MaxConcurrentStreams < streamsPerConnection {
		return nil, errors.New("Juicity max_concurrent_streams must be at least 30")
	}
	if o.AuthTimeout == 0 {
		o.AuthTimeout = defaultAuthTimeout
	}
	if o.UDPTimeout == 0 {
		o.UDPTimeout = defaultUDPTimeout
	}
	if o.AuthTimeout < 0 || o.UDPTimeout < 0 {
		return nil, errors.New("negative Juicity timeout")
	}
	ctx, cancel := context.WithCancel(o.Context)
	s := &Service{options: o, sessions: make(map[*serverSession]User), ctx: ctx, cancel: cancel}
	empty := make(map[[16]byte]User)
	s.users.Store(&empty)
	return s, nil
}

func (s *Service) UpdateUsers(users []User) error {
	table := make(map[[16]byte]User, len(users))
	for _, u := range users {
		if u.Password == "" {
			return errors.New("missing Juicity password")
		}
		if _, ok := table[u.UUID]; ok {
			return errors.New("duplicate Juicity UUID")
		}
		table[u.UUID] = u
	}
	s.mu.Lock()
	s.users.Store(&table)
	revoked := s.detachLocked(func(u User) bool { return table[u.UUID] != u })
	s.mu.Unlock()
	for _, session := range revoked {
		session.close()
	}
	return nil
}

func (s *Service) CloseUserSessions(name string) int {
	s.mu.Lock()
	revoked := s.detachLocked(func(u User) bool { return u.Name == name })
	s.mu.Unlock()
	for _, session := range revoked {
		session.close()
	}
	return len(revoked)
}

// Invalidate routing before releasing mu, then close transports outside the
// registry lock so an unrelated handshake can proceed during revocation.
func (s *Service) detachLocked(match func(User) bool) []*serverSession {
	var revoked []*serverSession
	for session, user := range s.sessions {
		if match(user) {
			session.cancel()
			delete(s.sessions, session)
			revoked = append(revoked, session)
		}
	}
	return revoked
}

func (s *Service) Start(conn net.PacketConn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return net.ErrClosed
	}
	if s.transport != nil {
		return errors.New("Juicity service already started")
	}
	config, err := s.options.TLSConfig.STDConfig()
	if err != nil {
		return err
	}
	config = config.Clone()
	config.MinVersion = tls.VersionTLS13
	config.NextProtos = []string{"h3"}
	t := &quic.Transport{Conn: conn}
	quicOptions := quicConfig(s.options.QUICOptions, s.options.TLSConfig.HandshakeTimeout())
	quicOptions.MaxIncomingUniStreams = 1
	l, err := t.Listen(config, quicOptions)
	if err != nil {
		_ = t.Close()
		return err
	}
	s.transport = t
	s.underlay = newUnderlayServer(s, t)
	go s.underlay.run()
	go func() {
		for {
			c, err := l.Accept(s.ctx)
			if err != nil {
				if s.ctx.Err() == nil && !errors.Is(err, quic.ErrServerClosed) {
					s.options.Logger.Error("Juicity listener: ", err)
				}
				return
			}
			go s.serve(c)
		}
	}()
	return nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	s.cancel()
	t, hub := s.transport, s.underlay
	s.mu.Unlock()
	if t != nil {
		hub.close()
		return t.Close()
	}
	return nil
}

type serverSession struct {
	*Service
	conn      *quic.Conn
	ctx       context.Context
	cancel    context.CancelFunc
	user      User
	closeOnce sync.Once
}

func (s *serverSession) close() {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.conn.CloseWithError(0, "")
		s.underlay.removeSession(s)
	})
}

func (s *Service) serve(c *quic.Conn) {
	ctx, cancel := context.WithCancel(c.Context())
	session := &serverSession{Service: s, conn: c, ctx: ctx, cancel: cancel}
	defer func() {
		session.close()
		s.mu.Lock()
		delete(s.sessions, session)
		s.mu.Unlock()
	}()
	setCongestion(s.ctx, c, s.options.CongestionControl)
	authCtx, stop := context.WithTimeout(ctx, s.options.AuthTimeout)
	control, err := c.AcceptUniStream(authCtx)
	if err != nil {
		stop()
		return
	}
	deadline, _ := authCtx.Deadline()
	_ = control.SetReadDeadline(deadline)
	var frame [authSize]byte
	_, err = io.ReadFull(control, frame[:])
	stop()
	if err != nil {
		return
	}
	user, err := verifyAuth(c.ConnectionState().TLS, frame, *s.users.Load())
	if err != nil {
		return
	}
	s.mu.Lock()
	if current, ok := (*s.users.Load())[user.UUID]; !ok || current != user {
		s.mu.Unlock()
		return
	}
	s.sessions[session] = user
	session.user = user
	s.mu.Unlock()
	_ = control.SetReadDeadline(time.Time{})
	go session.registrations(control)
	for {
		stream, err := c.AcceptStream(ctx)
		if err != nil {
			return
		}
		go session.handleStream(stream)
	}
}

func (s *serverSession) registrations(r *quic.ReceiveStream) {
	for {
		reg, err := readRegistration(r)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil || !s.underlay.register(s, reg) {
			s.close()
			return
		}
	}
}

func (s *serverSession) handleStream(stream *quic.Stream) {
	conn := &streamConn{Stream: stream, connection: s.conn}
	kind, dst, err := readHeader(stream)
	if err != nil || s.ctx.Err() != nil {
		_ = conn.Close()
		return
	}
	ctx := auth.ContextWithUser(s.ctx, s.user.Name)
	source := M.SocksaddrFromNet(s.conn.RemoteAddr()).Unwrap()
	if kind == networkTCP {
		s.options.Handler.NewConnectionEx(ctx, conn, source, dst, nil)
		return
	}
	s.routePackets(ctx, conn, source)
}
