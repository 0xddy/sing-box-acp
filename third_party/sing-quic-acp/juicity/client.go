package juicity

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ClientOptions struct {
	Context                    context.Context
	Dialer                     N.Dialer
	ServerAddress              M.Socksaddr
	TLSConfig                  aTLS.Config
	QUICOptions                qtls.QUICOptions
	User                       User
	UDPMode, CongestionControl string
}

type Client struct {
	options  ClientOptions
	mu       sync.Mutex
	sessions map[*clientSession]struct{}
	current  *clientSession
	// Serialize connection creation, but let other callers abandon the wait.
	dialing   chan struct{}
	epoch     context.Context
	cancel    context.CancelFunc
	closed    bool
	closeIdle bool
}

type clientSession struct {
	conn              *quic.Conn
	raw               net.Conn
	control           *quic.SendStream
	controlMu         sync.Mutex
	firstRegistration time.Time
	streams, refs     int // protected by Client.mu
}

func NewClient(o ClientOptions) (*Client, error) {
	if o.Context == nil || o.Dialer == nil || o.TLSConfig == nil {
		return nil, errors.New("Juicity client requires a context, dialer and TLS config")
	}
	if !o.ServerAddress.IsValid() || o.ServerAddress.Port == 0 {
		return nil, errors.New("Juicity server address and port are required")
	}
	if err := validCongestion(o.CongestionControl); err != nil {
		return nil, err
	}
	switch o.UDPMode {
	case "", "auto", "stream", "underlay":
	default:
		return nil, errors.New("invalid Juicity udp_mode: " + o.UDPMode)
	}
	if o.User.Password == "" {
		return nil, errors.New("missing Juicity password")
	}
	ctx, cancel := context.WithCancel(o.Context)
	return &Client{options: o, sessions: make(map[*clientSession]struct{}), dialing: make(chan struct{}, 1), epoch: ctx, cancel: cancel}, nil
}

func (c *Client) connect(ctx context.Context) (*clientSession, error) {
	raw, err := c.options.Dialer.DialContext(ctx, N.NetworkUDP, c.options.ServerAddress)
	if err != nil {
		return nil, err
	}
	conn, err := qtls.Dial(ctx, raw, c.options.TLSConfig, quicConfig(c.options.QUICOptions, c.options.TLSConfig.HandshakeTimeout()))
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	setCongestion(ctx, conn, c.options.CongestionControl)
	control, err := conn.OpenUniStreamSync(ctx)
	if err == nil {
		var frame [authSize]byte
		frame, err = authFrame(conn.ConnectionState().TLS, c.options.User)
		if err == nil {
			_ = control.SetWriteDeadline(time.Now().Add(defaultAuthTimeout))
			_, err = control.Write(frame[:])
			_ = control.SetWriteDeadline(time.Time{})
		}
	}
	if err != nil {
		_ = conn.CloseWithError(0, "")
		_ = raw.Close()
		return nil, err
	}
	// v0.5.0 parses auth using a buffered reader and then discards that reader.
	// Coalescing a registration with auth can lose the registration. Give auth
	// its own flight on a fresh session; TCP and stream UDP never wait for this.
	delay := max(10*time.Millisecond, 2*conn.ConnectionStats().SmoothedRTT)
	return &clientSession{conn: conn, raw: raw, control: control, firstRegistration: time.Now().Add(delay)}, nil
}

// Reserve a session while opening a stream or while an Underlay mapping exists.
// A full connection drains its existing streams before its socket is closed.
func (c *Client) acquire(ctx context.Context, stream bool) (*clientSession, error) {
	c.mu.Lock()
	epoch := c.epoch
	c.mu.Unlock()
	select {
	case c.dialing <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-epoch.Done():
		return nil, net.ErrClosed
	}
	defer func() { <-c.dialing }()
	c.mu.Lock()
	if epoch.Err() != nil {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	s := c.current
	if s != nil && s.conn.Context().Err() == nil && (!stream || s.streams < streamsPerConnection) {
		s.refs++
		if stream {
			s.streams++
		}
		c.mu.Unlock()
		return s, nil
	}
	c.current = nil
	if s != nil && s.refs == 0 {
		s.shutdown()
	}
	c.mu.Unlock()
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(epoch, cancel)
	s, err := c.connect(dialCtx)
	stop()
	cancel()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if epoch.Err() != nil {
		s.shutdown()
		return nil, net.ErrClosed
	}
	c.sessions[s] = struct{}{}
	c.current = s
	s.refs = 1
	if stream {
		s.streams = 1
	}
	context.AfterFunc(s.conn.Context(), func() {
		_ = s.raw.Close()
		c.mu.Lock()
		delete(c.sessions, s)
		if c.current == s {
			c.current = nil
		}
		c.mu.Unlock()
	})
	return s, nil
}

func (s *clientSession) shutdown() { _ = s.conn.CloseWithError(0, ""); _ = s.raw.Close() }

func (c *Client) release(s *clientSession) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s.refs--
	if s.refs == 0 && (s != c.current || c.closeIdle) {
		if c.current == s {
			c.current = nil
		}
		s.shutdown()
	}
}

func (c *Client) openStream(ctx context.Context, kind byte, dst M.Socksaddr) (*streamConn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		s, err := c.acquire(ctx, true)
		if err != nil {
			return nil, err
		}
		stream, err := s.conn.OpenStream()
		if err != nil {
			c.mu.Lock()
			if c.current == s {
				c.current = nil
			}
			c.mu.Unlock()
			c.release(s)
			var full *quic.StreamLimitReachedError
			if attempt == 0 && (errors.As(err, &full) || s.conn.Context().Err() != nil) {
				continue
			}
			return nil, err
		}
		conn := &streamConn{Stream: stream, connection: s.conn, release: func() { c.release(s) }}
		if err = writeHeader(stream, kind, dst); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
	return nil, errors.New("Juicity stream capacity exhausted")
}

func (c *Client) DialConn(ctx context.Context, dst M.Socksaddr) (net.Conn, error) {
	return c.openStream(ctx, networkTCP, dst)
}

func (c *Client) CloseIdleConnections() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeIdleLocked()
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeIdle = !keep
	if !keep {
		c.closeIdleLocked()
	}
}

func (c *Client) closeIdleLocked() {
	if s := c.current; s != nil && s.refs == 0 {
		c.current = nil
		s.shutdown()
	}
}

func (c *Client) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.cancel()
	for s := range c.sessions {
		s.shutdown()
	}
	c.current = nil
	c.epoch, c.cancel = context.WithCancel(c.options.Context)
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.cancel()
	for s := range c.sessions {
		s.shutdown()
	}
	c.current = nil
	return nil
}
