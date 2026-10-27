// Package webserver serves already decrypted connections without opening a public listener.
package webserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/sagernet/sing-box/common/webprofile"
	"github.com/sagernet/sing/common/logger"
	"golang.org/x/net/http2"
)

const maxConnections = 256

type Server struct {
	http            *http.Server
	h2              *http2.Server
	listener        *connectionListener
	logger          logger.ContextLogger
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	started, closed bool
	connections     map[*connection]struct{}
	wg              sync.WaitGroup
}

type stateKey struct{}
type connectionKey struct{}

func New(handler http.Handler, logger logger.ContextLogger) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{logger: logger, ctx: ctx, cancel: cancel, connections: make(map[*connection]struct{}), listener: &connectionListener{queue: make(chan net.Conn, maxConnections), done: make(chan struct{})}}
	s.http = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if state, ok := r.Context().Value(stateKey{}).(tls.ConnectionState); ok {
				r.TLS = &state
			}
			if c, ok := r.Context().Value(connectionKey{}).(*connection); ok && c.http1 != nil {
				if c.http1.begin(r) {
					w.Header().Set("Connection", "close")
				}
			}
			if status, note := validateWebsiteRequest(r); status != 0 {
				if r.ProtoMajor == 1 {
					w.Header().Set("Connection", "close")
				}
				webprofile.WriteError(w, r, status, note)
				return
			}
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: profileHeaderTimeout, ReadTimeout: profileIOTimeout,
		WriteTimeout: profileIOTimeout, IdleTimeout: profileIdleTimeout,
		MaxHeaderBytes: maxRequestHeaderBytes,
		// Let the website answer OPTIONS * with its own Allow and Server
		// headers instead of net/http's built-in empty response.
		DisableGeneralOptionsHandler: true,
		BaseContext:                  func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			ctx = context.WithValue(ctx, stateKey{}, c.(*connection).state)
			return context.WithValue(ctx, connectionKey{}, c.(*connection))
		},
	}
	s.h2 = newHTTP2Server()
	return s
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.started {
		return nil
	}
	s.started = true
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if value := recover(); value != nil {
				s.logger.Error("web listener panic: ", value)
				s.cancel()
			}
		}()
		if err := s.http.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			s.logger.Error("web listener: ", err)
		}
	}()
	return nil
}

// Serve transfers ownership only on success. The callback runs once when the connection closes.
func (s *Server) Serve(conn net.Conn, state tls.ConnectionState, onClose func(error)) error {
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" && state.NegotiatedProtocol != "h2" {
		return fmt.Errorf("unsupported web ALPN: %s", state.NegotiatedProtocol)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started || s.closed {
		return net.ErrClosed
	}
	if len(s.connections) >= maxConnections {
		return errors.New("web connection limit reached")
	}
	c := &connection{Conn: conn, state: state, owner: s, onClose: onClose}
	if state.NegotiatedProtocol == "h2" {
		c.Conn = &http2Profile{Conn: conn}
	} else {
		c.http1 = newHTTP1Profile(conn)
		c.Conn = c.http1
	}
	s.connections[c] = struct{}{}
	if state.NegotiatedProtocol == "h2" {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			defer func() {
				if value := recover(); value != nil {
					s.logger.Error("web HTTP/2 panic: ", value)
				}
			}()
			s.h2.ServeConn(c, &http2.ServeConnOpts{Context: context.WithValue(s.ctx, stateKey{}, state), BaseConfig: s.http})
		}()
	} else {
		s.listener.queue <- c
	}
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()
	connections := make([]*connection, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.mu.Unlock()
	listenerErr := s.listener.Close()
	serverErr := s.http.Close()
	for _, conn := range connections {
		if err := conn.Close(); err != nil {
			s.logger.Debug("close web connection: ", err)
		}
	}
	s.wg.Wait()
	return errors.Join(listenerErr, serverErr)
}

type connection struct {
	net.Conn
	http1   *http1Profile
	state   tls.ConnectionState
	owner   *Server
	onClose func(error)
	once    sync.Once
	err     error
}

func (c *connection) ConnectionState() tls.ConnectionState { return c.state }
func (c *connection) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.owner.mu.Lock()
		delete(c.owner.connections, c)
		c.owner.mu.Unlock()
		if c.onClose != nil {
			c.onClose(c.err)
		}
	})
	return c.err
}

type connectionListener struct {
	queue chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *connectionListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case c := <-l.queue:
		return c, nil
	}
}
func (l *connectionListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (*connectionListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
