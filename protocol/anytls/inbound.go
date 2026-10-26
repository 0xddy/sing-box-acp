package anytls

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	"github.com/sagernet/sing-box/common/webcontent"
	"github.com/sagernet/sing-box/common/webserver"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/anytls/sing-anytls/padding"
	"github.com/anytls/sing-anytls/session"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.AnyTLSInboundOptions](registry, C.TypeAnyTLS, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	cancel      context.CancelFunc
	tlsConfig   tls.ServerConfig
	router      adapter.ConnectionRouterEx
	logger      logger.ContextLogger
	listener    *listener.Listener
	padding     atomic.TypedValue[*padding.PaddingFactory]
	users       *authentication
	mu          sync.Mutex
	closed      bool
	connections map[net.Conn]*identity
	wg          sync.WaitGroup
	web         *webserver.Server
	content     *webcontent.Site
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSInboundOptions) (created adapter.Inbound, err error) {
	ctx, cancel := context.WithCancel(ctx)
	inbound := &Inbound{
		Adapter:     inbound.NewAdapter(C.TypeAnyTLS, tag),
		cancel:      cancel,
		router:      uot.NewRouter(router, logger),
		logger:      logger,
		connections: make(map[net.Conn]*identity),
	}
	defer func() {
		if err != nil {
			cancel()
			err = errors.Join(err, inbound.closeWeb(), common.Close(inbound.tlsConfig))
		}
	}()

	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}

	paddingScheme := padding.DefaultPaddingScheme
	if len(options.PaddingScheme) > 0 {
		paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	}

	if !padding.UpdatePaddingScheme(paddingScheme, &inbound.padding) {
		return nil, fmt.Errorf("invalid AnyTLS padding scheme")
	}
	if err := inbound.UpdateUsers(options.Users); err != nil {
		return nil, err
	}
	if options.Web != nil {
		if inbound.tlsConfig == nil {
			return nil, fmt.Errorf("AnyTLS web fallback requires TLS")
		}
		content, err := webcontent.New(*options.Web)
		if err != nil {
			return nil, err
		}
		inbound.content = content
		inbound.web = webserver.New(content, logger)
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
	if h.web != nil {
		if err := h.web.Start(); err != nil {
			return err
		}
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	h.cancel()
	h.mu.Lock()
	h.closed = true
	connections := make([]net.Conn, 0, len(h.connections))
	for conn := range h.connections {
		connections = append(connections, conn)
	}
	h.mu.Unlock()
	err := common.Close(h.listener)
	for _, conn := range connections {
		h.closeConnection(conn)
	}
	err = errors.Join(err, h.closeWeb(), common.Close(h.tlsConfig))
	h.wg.Wait()
	return err
}

func (h *Inbound) closeWeb() error {
	var err error
	if h.web != nil {
		err = h.web.Close()
	}
	if h.content != nil {
		err = errors.Join(err, h.content.Close())
	}
	return err
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	rawConn := conn
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		// The rejection is already delivered through the close callback.
		_ = N.CloseOnHandshakeFailure(conn, onClose, net.ErrClosed)
		return
	}
	h.wg.Add(1)
	h.connections[rawConn] = nil
	users := h.users
	h.mu.Unlock()
	defer h.wg.Done()
	handedOff := false
	var result error
	defer func() {
		h.mu.Lock()
		delete(h.connections, rawConn)
		h.mu.Unlock()
		if !handedOff {
			if err := N.CloseOnHandshakeFailure(conn, onClose, result); err != nil {
				h.logger.DebugContext(ctx, "AnyTLS connection: ", err)
			}
		}
	}()
	var state tls.ConnectionState
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			result = err
			return
		}
		conn, state = tlsConn, tlsConn.ConnectionState()
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		result = err
		return
	}
	reader := bufio.NewReader(conn)
	user, prefix, err := identify(reader, users)
	if err != nil {
		result = err
		return
	}
	if user == nil {
		if h.web == nil {
			result = fmt.Errorf("AnyTLS authentication rejected")
			return
		}
		if err = conn.SetReadDeadline(time.Time{}); err != nil {
			result = err
			return
		}
		replay := &readConnection{Conn: conn, reader: io.MultiReader(bytes.NewReader(prefix), reader)}
		result = h.web.Serve(replay, state, onClose)
		handedOff = result == nil
		return
	}
	h.mu.Lock()
	if h.closed || !h.users.contains(*user) {
		h.mu.Unlock()
		result = fmt.Errorf("AnyTLS credential revoked")
		return
	}
	h.connections[rawConn] = user
	h.mu.Unlock()
	var paddingLength uint16
	if err = binary.Read(reader, binary.BigEndian, &paddingLength); err != nil {
		result = err
		return
	}
	if _, err = io.CopyN(io.Discard, reader, int64(paddingLength)); err != nil {
		result = err
		return
	}
	if err = conn.SetReadDeadline(time.Time{}); err != nil {
		result = err
		return
	}
	ctx = auth.ContextWithUser(adapter.WithContext(ctx, &metadata), user.name)
	transport := &readConnection{Conn: conn, reader: reader}
	active := session.NewServerSession(transport, func(stream *session.Stream) {
		defer func() {
			if value := recover(); value != nil {
				h.closeConnection(stream)
				h.logger.ErrorContext(ctx, "AnyTLS stream panic: ", value)
			}
		}()
		destination, readErr := M.SocksaddrSerializer.ReadAddrPort(stream)
		if readErr != nil {
			h.closeConnection(stream)
			h.logger.DebugContext(ctx, "AnyTLS stream destination: ", readErr)
			return
		}
		(*inboundHandler)(h).NewConnectionEx(ctx, stream, metadata.Source, destination, nil)
	}, &h.padding, h.logger)
	defer func() {
		if err := active.Close(); err != nil && !errors.Is(err, io.ErrClosedPipe) {
			h.logger.DebugContext(ctx, "close AnyTLS session: ", err)
		}
	}()
	active.Run()
}

func (h *Inbound) closeConnection(conn net.Conn) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		h.logger.Debug("close AnyTLS connection: ", err)
	}
}

type readConnection struct {
	net.Conn
	reader io.Reader
}

func (c *readConnection) Read(p []byte) (int, error) { return c.reader.Read(p) }

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}
