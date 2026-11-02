package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Client struct {
	ctx       context.Context
	up, down  url.URL
	server    M.Socksaddr
	dialer    tls.Dialer
	opts      Options
	codec     *codec
	mu        sync.Mutex
	group     *muxGroup
	closeIdle atomic.Bool
}

func NewClient(ctx context.Context, dialer N.Dialer, server M.Socksaddr, opts Options, config tls.Config) (*Client, error) {
	opts, err := normalizeOptions(opts, config)
	if err != nil {
		return nil, err
	}
	if opts.Mode == ModeAuto {
		opts.Mode = ModePacketUp
		if isReality(config) {
			opts.Mode = ModeStreamOne
			if opts.DownloadSettings != nil {
				opts.Mode = ModeStreamUp
			}
		}
	}
	if err := validateMode(opts); err != nil {
		return nil, err
	}
	config.SetNextProtos([]string{"h2"})
	host := opts.Host
	if host == "" {
		host = config.ServerName()
	}
	if host == "" {
		host = server.AddrString()
	}
	up, err := endpointURL(host, opts.Path)
	if err != nil {
		return nil, err
	}
	down := up
	if d := opts.DownloadSettings; d != nil {
		h, p := d.Host, d.Path
		if h == "" {
			h = host
		}
		if p == "" {
			p = opts.Path
		}
		down, err = endpointURL(h, p)
		if err != nil {
			return nil, err
		}
	}
	return &Client{ctx: ctx, up: up, down: down, server: server, dialer: tls.NewDialer(dialer, config), opts: opts, codec: newCodec(opts)}, nil
}

func (c *Client) dialTLS(poolCtx, ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(poolCtx, cancel)
	defer cancel()
	defer stop()
	conn, err := c.dialer.DialTLSContext(adapter.ContextForMultiplexSession(ctx), c.server)
	if err != nil {
		return nil, err
	}
	// REALITY can negotiate no ALPN and still accept the h2 preface.
	if alpn := conn.ConnectionState().NegotiatedProtocol; alpn != "" && alpn != "h2" {
		conn.Close()
		return nil, E.New("XHTTP: incompatible ALPN: ", alpn)
	}
	return &poolConn{conn, context.AfterFunc(poolCtx, func() { conn.Close() })}, nil
}

type poolConn struct {
	tls.Conn
	stop func() bool
}

func (p *poolConn) Close() error { p.stop(); return p.Conn.Close() }

func (c *Client) currentGroup() *muxGroup {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.group == nil {
		c.group = newMuxGroup(c.ctx, c.opts.Xmux, c.dialTLS)
	}
	return c.group
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	group := c.currentGroup()
	pool := group.acquire()
	requestCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stopReset := context.AfterFunc(group.ctx, cancel)
	stopDial := context.AfterFunc(ctx, cancel)
	defer stopDial()
	keep := adapter.KeepSessionFromContext(ctx)
	conn, input, output := newStream(M.Socksaddr{}, c.server, func() {
		stopReset()
		cancel()
		group.release(pool)
		if c.closeIdle.Load() && !keep {
			pool.transport.CloseIdleConnections()
		}
	})
	context.AfterFunc(requestCtx, func() { conn.Close() })
	if err := c.startStream(requestCtx, conn, input, output, group, pool); err != nil {
		conn.Close()
		input.Close()
		output.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) startStream(ctx context.Context, conn *streamConn, input, output net.Conn, group *muxGroup, pool *muxPool) error {
	endpoint, method, id := c.up, c.opts.Method, ""
	var body io.Reader = output
	if c.opts.Mode != ModeStreamOne {
		endpoint, method, id = c.down, http.MethodGet, c.codec.generateSessionID()
		body = nil
	}
	req, err := c.codec.request(ctx, c.opts, endpoint, method, id, "", body)
	if err != nil {
		return err
	}
	// Split downloads can be buffered by a reverse proxy until the first upload.
	// Unblock the dial when the GET is on the wire, rather than waiting for its response.
	started := make(chan struct{})
	if id != "" {
		var once sync.Once
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{WroteHeaders: func() { once.Do(func() { close(started) }) }}))
	}
	result := make(chan error, 1)
	go func() {
		resp, err := group.send(pool, req)
		result <- err
		if err != nil {
			conn.failRead(input, err)
			conn.Close()
			return
		}
		defer resp.Body.Close()
		if err := conn.receive(input, resp.Body); err != nil {
			conn.Close()
		}
	}()
	timer := time.NewTimer(C.TCPTimeout)
	defer timer.Stop()
	select {
	case err := <-result:
		if err != nil {
			return err
		}
	case <-started:
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return E.New("XHTTP: download handshake timed out")
	}
	if id != "" {
		go func() {
			defer output.Close()
			if err := c.upload(ctx, output, id, group, pool); err != nil && ctx.Err() == nil {
				conn.setError(err)
				conn.Close()
			}
		}()
	}
	return nil
}

func (c *Client) MultiplexEnabled() bool { return true }

func (c *Client) SetKeepIdleConnections(keep bool) { c.closeIdle.Store(!keep) }

func (c *Client) CloseIdleConnections() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.group != nil {
		c.group.closeIdle()
	}
}

func (c *Client) Close() error {
	c.mu.Lock()
	group := c.group
	c.group = nil
	c.mu.Unlock()
	if group != nil {
		group.cancel()
		group.closeIdle()
	}
	return nil
}
