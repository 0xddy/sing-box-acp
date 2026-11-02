package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/http2"
)

type muxGroup struct {
	ctx                            context.Context
	cancel                         context.CancelFunc
	mu                             sync.Mutex
	pools                          map[*muxPool]struct{}
	opts                           option.XHTTPMuxOptions
	maxConnections, maxConcurrency int32
	dial                           func(context.Context, context.Context) (net.Conn, error)
}
type muxPool struct {
	transport                *http2.Transport
	cancel                   context.CancelFunc
	active, uses, requests   int
	reuseLimit, requestLimit int32
	expires                  time.Time
}

func newMuxGroup(ctx context.Context, opts *option.XHTTPMuxOptions, dial func(context.Context, context.Context) (net.Conn, error)) *muxGroup {
	ctx, cancel := context.WithCancel(ctx)
	g := &muxGroup{ctx: ctx, cancel: cancel, dial: dial, pools: make(map[*muxPool]struct{})}
	if opts == nil || *opts == (option.XHTTPMuxOptions{}) {
		g.opts = option.XHTTPMuxOptions{MaxConnections: &Range{From: 3, To: 3}, HMaxRequestTimes: &Range{From: 600, To: 900}, HMaxReusableSecs: &Range{From: 1800, To: 3000}}
	} else {
		g.opts = *opts
	}
	g.maxConnections = roll(g.opts.MaxConnections)
	g.maxConcurrency = roll(g.opts.MaxConcurrency)
	return g
}

func roll(r *Range) int32 { return rangeRand(orRange(r, Range{})) }

func (p *muxPool) spent() bool {
	return (p.requestLimit > 0 && p.requests >= int(p.requestLimit)) || (!p.expires.IsZero() && time.Now().After(p.expires))
}

func (p *muxPool) reused() bool { return p.reuseLimit > 0 && p.uses >= int(p.reuseLimit) }

func (g *muxGroup) acquire() *muxPool { g.mu.Lock(); defer g.mu.Unlock(); return g.acquireLocked() }

func (g *muxGroup) acquireLocked() *muxPool {
	var best *muxPool
	available := 0
	for p := range g.pools {
		if p.spent() || p.reused() {
			if p.active == 0 {
				g.retireLocked(p)
			}
			continue
		}
		available++
		if g.maxConcurrency > 0 && p.active >= int(g.maxConcurrency) {
			continue
		}
		if best == nil || p.active < best.active {
			best = p
		}
	}
	if best == nil || available < int(g.maxConnections) {
		ctx, cancel := context.WithCancel(g.ctx)
		ping := g.opts.HKeepAlivePeriod
		if ping == 0 {
			ping = 30
		}
		if ping < 0 {
			ping = 0
		}
		best = &muxPool{cancel: cancel, reuseLimit: roll(g.opts.CMaxReuseTimes), requestLimit: roll(g.opts.HMaxRequestTimes), transport: &http2.Transport{
			IdleConnTimeout: time.Minute, ReadIdleTimeout: time.Duration(ping) * time.Second,
			DialTLSContext: func(dialCtx context.Context, _, _ string, _ *tls.STDConfig) (net.Conn, error) {
				return g.dial(ctx, dialCtx)
			},
		}}
		if secs := roll(g.opts.HMaxReusableSecs); secs > 0 {
			best.expires = time.Now().Add(time.Duration(secs) * time.Second)
		}
		g.pools[best] = struct{}{}
	}
	best.uses++
	best.active++
	return best
}

func (g *muxGroup) retireLocked(p *muxPool) {
	delete(g.pools, p)
	p.cancel()
	p.transport.CloseIdleConnections()
}

func (g *muxGroup) release(p *muxPool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p.active--
	if p.active == 0 && (p.spent() || p.reused() || g.ctx.Err() != nil) {
		g.retireLocked(p)
	}
}

func (g *muxGroup) closeIdle() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for p := range g.pools {
		p.transport.CloseIdleConnections()
	}
}

func (g *muxGroup) send(p *muxPool, req *http.Request) (*http.Response, error) {
	g.mu.Lock()
	if p.spent() {
		p = g.acquireLocked()
	} else {
		p.active++
	}
	p.requests++
	g.mu.Unlock()
	resp, err := p.transport.RoundTrip(req)
	if err == nil && resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		err = E.New("XHTTP: ", resp.Status)
	}
	if err != nil {
		g.release(p)
		return nil, err
	}
	resp.Body = &leasedBody{ReadCloser: resp.Body, release: func() { g.release(p) }}
	return resp, nil
}

type leasedBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *leasedBody) Close() error { defer b.once.Do(b.release); return b.ReadCloser.Close() }
