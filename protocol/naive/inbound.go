package naive

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	uotprotocol "github.com/sagernet/sing/common/uot"
	sHttp "github.com/sagernet/sing/protocol/http"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var (
	ConfigureHTTP3ListenerFunc func(context.Context, logger.Logger, *listener.Listener, http.Handler, tls.ServerConfig, option.NaiveInboundOptions) (io.Closer, error)
	WrapError                  func(error) error
)

const MaxTransportConnections = 256
const MaxConcurrentStreams = 100
const maxAuthenticatedFlows = 4096

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.NaiveInboundOptions](registry, C.TypeNaive, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	ctx            context.Context
	cancel         context.CancelFunc
	router         adapter.ConnectionRouterEx
	logger         logger.ContextLogger
	options        option.NaiveInboundOptions
	listener       *listener.Listener
	network        []string
	tlsConfig      tls.ServerConfig
	httpServer     *http.Server
	http3Server    io.Closer
	web            *webserver.Server
	site           *webcontent.Site
	mu             sync.Mutex
	users          map[string]userIdentity
	flows          map[*userFlow]userIdentity
	transports     map[*transportConn]struct{}
	transportCount int
	closed         bool
	runtimeErr     error
	wg             sync.WaitGroup
	requests       sync.WaitGroup
	closeOnce      sync.Once
	closeErr       error
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveInboundOptions) (adapter.Inbound, error) {
	users, err := authenticationFor(options.Users)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	n := &Inbound{Adapter: inbound.NewAdapter(C.TypeNaive, tag), ctx: ctx, cancel: cancel,
		router: uot.NewRouter(router, logger), logger: logger, options: options, network: options.Network.Build(),
		users: users, flows: make(map[*userFlow]userIdentity), transports: make(map[*transportConn]struct{})}
	n.listener = listener.New(listener.Options{Context: ctx, Logger: logger, Listen: options.ListenOptions})
	if (common.Contains(n.network, N.NetworkUDP) || options.Web != nil) && (options.TLS == nil || !options.TLS.Enabled) {
		cancel()
		return nil, E.New("TLS is required for Naive QUIC and web server")
	}
	if options.TLS != nil {
		n.tlsConfig, err = tls.NewServer(ctx, logger, *options.TLS)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	if options.Web != nil {
		n.site, err = webcontent.New(*options.Web)
		if err != nil {
			cancel()
			_ = common.Close(n.tlsConfig)
			return nil, err
		}
		n.web = webserver.NewForConnect(n, logger)
	}
	return n, nil
}

func (n *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) (err error) {
	if stage != adapter.StartStateStart {
		return nil
	}
	scope.Add(n.Close)
	defer func() {
		if err != nil {
			_ = n.Close()
		}
	}()
	if n.tlsConfig != nil {
		n.tlsConfig.SetNextProtos([]string{"h2", "http/1.1"})
		if err = n.tlsConfig.Start(); err != nil {
			return err
		}
	}
	if n.web != nil {
		if err = n.web.Start(); err != nil {
			return err
		}
	}
	// Initialize QUIC before serving TCP: HTTP/3 may extend the shared ALPN list.
	if common.Contains(n.network, N.NetworkUDP) {
		if ConfigureHTTP3ListenerFunc == nil {
			return E.New("Naive HTTP/3 is not initialized")
		}
		n.http3Server, err = ConfigureHTTP3ListenerFunc(n.ctx, n.logger, n.listener, n, n.tlsConfig, n.options)
		if err != nil {
			return err
		}
	}
	if common.Contains(n.network, N.NetworkTCP) {
		var tcp net.Listener
		tcp, err = n.listener.ListenTCP()
		if err != nil {
			return err
		}
		if n.web != nil {
			n.wg.Add(1)
			go n.serveTCP(tcp)
		} else {
			// Preserve standalone h2c use. ACP always enables Web/TLS.
			n.httpServer = &http.Server{Handler: h2c.NewHandler(n, &http2.Server{MaxConcurrentStreams: MaxConcurrentStreams}), BaseContext: func(net.Listener) context.Context { return n.ctx }}
			tcp = &boundedListener{Listener: tcp, owner: n}
			if n.tlsConfig != nil {
				tcp = aTLS.NewListener(tcp, n.tlsConfig)
			}
			n.wg.Add(1)
			go func() { defer n.wg.Done(); defer n.recoverRuntime(); n.ReportRuntimeError(n.httpServer.Serve(tcp)) }()
		}
	}
	return nil
}

func (n *Inbound) serveTCP(tcp net.Listener) {
	defer n.wg.Done()
	defer n.recoverRuntime()
	for {
		conn, err := tcp.Accept()
		if err != nil {
			n.ReportRuntimeError(err)
			return
		}
		owned := n.ownTransport(conn)
		if owned == nil {
			_ = conn.Close()
			continue
		}
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			defer n.recoverRuntime()
			handedOff := false
			defer func() {
				if !handedOff {
					_ = owned.Close()
				}
			}()
			_ = owned.SetDeadline(time.Now().Add(10 * time.Second))
			secured, err := tls.ServerHandshake(n.ctx, owned, n.tlsConfig)
			if err != nil {
				return
			}
			_ = secured.SetDeadline(time.Time{})
			if err = n.web.Serve(secured, secured.ConnectionState(), nil); err != nil {
				return
			}
			handedOff = true
		}()
	}
}

func (n *Inbound) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.requests.Add(1)
	n.mu.Unlock()
	defer n.requests.Done()
	if r.ProtoMajor == 3 && n.web != nil && r.Context().Value(webPolicyKey{}) == nil {
		n.web.Handler().ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), webPolicyKey{}, true)))
		return
	}
	user, password, ok := sHttp.ParseBasicAuth(r.Header.Get("Proxy-Authorization"))
	if r.Method != http.MethodConnect || r.Header.Get("Padding") == "" || !ok {
		n.serveWebsite(w, r)
		return
	}
	controller := http.NewResponseController(w)
	flow, authenticated := n.beginFlow(r.Context(), user, password)
	if !authenticated {
		n.serveWebsite(w, r)
		return
	}
	if flow == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(flow.ctx, func() {
		defer close(interrupted)
		// These are per-stream deadlines for HTTP/2 and HTTP/3.
		_ = controller.SetReadDeadline(time.Now())
		_ = controller.SetWriteDeadline(time.Now())
	})
	stopEarlyInterrupt := sync.OnceFunc(func() {
		if !stop() {
			<-interrupted
		}
	})
	defer func() {
		_ = flow.Close()
		stopEarlyInterrupt()
		n.endFlow(flow)
	}()
	if err := controller.SetReadDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return
	}
	if err := controller.SetWriteDeadline(time.Time{}); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return
	}
	if flow.ctx.Err() != nil {
		return
	}
	hostPort := r.URL.Host
	if hostPort == "" {
		hostPort = r.Host
	}
	if n.web == nil && r.Header.Get("-connect-authority") != "" {
		hostPort = r.Header.Get("-connect-authority")
	}
	destination := M.ParseSocksaddr(hostPort).Unwrap()
	// UoT v2 uses a reserved authority with port zero. Ordinary CONNECT
	// destinations must still carry a real port; authentication has already run.
	if !destination.IsValid() || (destination.Port == 0 && destination.Fqdn != uotprotocol.MagicAddress) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	source := M.ParseSocksaddr(r.RemoteAddr)
	w.Header().Set("Padding", generatePaddingHeader())
	w.WriteHeader(http.StatusOK)
	if err := controller.Flush(); err != nil {
		return
	}
	var conn net.Conn
	if r.ProtoMajor == 1 {
		raw, buffered, err := controller.Hijack()
		if err != nil {
			return
		}
		_ = raw.SetDeadline(time.Time{})
		if buffered.Reader.Buffered() > 0 {
			data := make([]byte, buffered.Reader.Buffered())
			if _, err = io.ReadFull(buffered.Reader, data); err != nil {
				_ = raw.Close()
				return
			}
			raw = bufio.NewCachedConn(raw, buf.As(data))
		}
		conn = &naiveConn{Conn: &writeProgressConn{Conn: raw}}
	} else {
		conn = newHTTPStream(r, w, controller, source)
	}
	if !flow.attach(conn) {
		return
	}
	// Once attached, the stream owns cancellation and write synchronization.
	// The early callback only guards authentication-to-handoff I/O.
	stopEarlyInterrupt()
	metadata := adapter.InboundContext{
		Inbound: n.Tag(), InboundType: n.Type(), User: user,
		InboundDetour: n.listener.ListenOptions().Detour,
		Source:        source, Destination: destination,
		OriginDestination: M.SocksaddrFromNet(conn.LocalAddr()).Unwrap(),
		Network:           N.NetworkTCP,
	}
	n.router.RouteConnectionEx(flow.ctx, flow, metadata, func(error) { _ = flow.Close() })
	<-flow.ctx.Done()
}

type webPolicyKey struct{}

func (n *Inbound) serveWebsite(w http.ResponseWriter, r *http.Request) {
	if n.site == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	r = r.Clone(r.Context())
	for _, key := range []string{"Proxy-Authorization", "Proxy-Connection", "Padding", "Padding-Type-Request", "-connect-authority"} {
		r.Header.Del(key)
	}
	n.site.ServeHTTP(w, r)
}

func (n *Inbound) UpdateTLSCertificate(cert *stdtls.Certificate) error {
	return tls.UpdateCertificate(n.tlsConfig, cert)
}
func (n *Inbound) ReportRuntimeError(err error) {
	if err == nil || errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) || E.IsClosedOrCanceled(err) {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.closed && n.runtimeErr == nil {
		n.runtimeErr = err
	}
}
func (n *Inbound) recoverRuntime() {
	if value := recover(); value != nil {
		n.ReportRuntimeError(fmt.Errorf("Naive server panic: %v", value))
	}
}
func (n *Inbound) RuntimeError() error {
	n.mu.Lock()
	err := n.runtimeErr
	n.mu.Unlock()
	if err == nil && n.web != nil {
		err = n.web.RuntimeError()
	}
	return err
}

func (n *Inbound) Close() error {
	n.closeOnce.Do(func() {
		n.mu.Lock()
		n.closed = true
		flows := make([]*userFlow, 0, len(n.flows))
		for f := range n.flows {
			flows = append(flows, f)
		}
		transports := make([]*transportConn, 0, len(n.transports))
		for c := range n.transports {
			transports = append(transports, c)
		}
		n.mu.Unlock()
		n.cancel()
		for _, f := range flows {
			_ = f.abort()
		}
		n.closeErr = common.Close(n.listener, n.http3Server)
		if n.httpServer != nil {
			n.closeErr = errors.Join(n.closeErr, n.httpServer.Close())
		}
		if n.web != nil {
			n.closeErr = errors.Join(n.closeErr, n.web.Close())
		}
		for _, c := range transports {
			_ = c.Close()
		}
		n.wg.Wait()
		n.requests.Wait()
		if n.site != nil {
			n.closeErr = errors.Join(n.closeErr, n.site.Close())
		}
		n.closeErr = errors.Join(n.closeErr, common.Close(n.tlsConfig))
	})
	return n.closeErr
}
