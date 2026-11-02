package juicity

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	maxPending      = 1024
	maxPendingBytes = 4 << 20
	maxAssociations = 4096
)

// An association is identified by its authenticated first salt, then by its UDP source.
// Traffic arriving before the control record is held briefly in a bounded queue.
type underlayServer struct {
	service    *Service
	transport  *quic.Transport
	mu         sync.Mutex
	grants     map[salt]grant
	early      map[salt]earlyPacket
	earlyBytes int
	peers      map[string]*serverPackets
}

type grant struct {
	registration
	owner   *serverSession
	expires time.Time
}

type earlyPacket struct {
	wire    []byte
	peer    net.Addr
	expires time.Time
}

type serverPackets struct {
	*packetInbox
	hub        *underlayServer
	grant      grant
	peer       net.Addr
	seen       saltWindow
	lastActive time.Time
}

// Never evict a salt while its key is live. A busy client renews its key
// before reaching this budget; a saturated receiver fails closed.
const saltsPerKey = 16384

// Both directions share a key. Remember emitted salts too so a reflected
// response cannot be accepted as a fresh request.
type saltWindow struct {
	mu   sync.Mutex
	seen map[salt]struct{}
}

var errSaltReuse = errors.New("Juicity Underlay key requires renewal")

func (w *saltWindow) accept(s salt) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.seen[s]; ok || len(w.seen) >= saltsPerKey {
		return false
	}
	if w.seen == nil {
		w.seen = make(map[salt]struct{})
	}
	w.seen[s] = struct{}{}
	return true
}

func newUnderlayServer(service *Service, t *quic.Transport) *underlayServer {
	return &underlayServer{service: service, transport: t, grants: make(map[salt]grant), early: make(map[salt]earlyPacket), peers: make(map[string]*serverPackets)}
}

func (h *underlayServer) run() {
	go h.expire()
	buf := make([]byte, 65535)
	for {
		n, peer, err := h.transport.ReadNonQUICPacket(h.service.ctx, buf)
		if err != nil {
			if h.service.ctx.Err() == nil {
				h.service.options.Logger.Error("Juicity Underlay listener: ", err)
			}
			return
		}
		h.mu.Lock()
		h.receive(buf[:n], peer, true)
		h.mu.Unlock()
	}
}

func (h *underlayServer) expire() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-h.service.ctx.Done():
			return
		case now := <-tick.C:
			h.prune(now)
		}
	}
}

func (h *underlayServer) prune(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s, g := range h.grants {
		if !now.Before(g.expires) {
			delete(h.grants, s)
		}
	}
	for s, p := range h.early {
		if !now.Before(p.expires) {
			h.removeEarly(s)
		}
	}
	for k, p := range h.peers {
		if p.ctx.Err() != nil || now.Sub(p.lastActive) >= h.service.options.UDPTimeout {
			delete(h.peers, k)
			_ = p.packetInbox.Close()
		}
	}
}

func (h *underlayServer) removeEarly(s salt) {
	h.earlyBytes -= len(h.early[s].wire)
	delete(h.early, s)
}

func (h *underlayServer) register(owner *serverSession, r registration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.service.ctx.Err() != nil || owner.ctx.Err() != nil || len(h.grants) >= maxPending {
		return false
	}
	if _, duplicate := h.grants[r.Salt]; duplicate {
		return false
	}
	h.grants[r.Salt] = grant{r, owner, time.Now().Add(defaultAuthTimeout)}
	if p, ok := h.early[r.Salt]; ok {
		h.removeEarly(r.Salt)
		if time.Now().Before(p.expires) {
			h.receive(p.wire, p.peer, false)
		}
	}
	return true
}

func (h *underlayServer) removeSession(owner *serverSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s, g := range h.grants {
		if g.owner == owner {
			delete(h.grants, s)
		}
	}
	for k, p := range h.peers {
		if p.grant.owner == owner {
			delete(h.peers, k)
			_ = p.packetInbox.Close()
		}
	}
}

func (h *underlayServer) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.peers {
		_ = p.packetInbox.Close()
	}
	clear(h.grants)
	clear(h.early)
	clear(h.peers)
	h.earlyBytes = 0
}

// Caller holds mu. Only authenticated plaintext can create a routed endpoint.
func (h *underlayServer) receive(wire []byte, peer net.Addr, queue bool) {
	if h.service.ctx.Err() != nil || len(wire) < 48 || wire[0] != 0 || wire[1] != 0 {
		return
	}
	s := salt(wire[:32])
	id := peer.String()
	p := h.peers[id]
	g, registered := h.grants[s]
	now := time.Now()
	if registered {
		if !now.Before(g.expires) || g.owner.ctx.Err() != nil {
			delete(h.grants, s)
			return
		}
	} else if p != nil {
		g = p.grant
	} else {
		if queue && len(h.early) < maxPending && h.earlyBytes+len(wire) <= maxPendingBytes {
			if _, ok := h.early[s]; !ok {
				h.early[s] = earlyPacket{append([]byte(nil), wire...), peer, now.Add(defaultAuthTimeout)}
				h.earlyBytes += len(wire)
			}
		}
		return
	}
	_, plain, err := openPacket(g.Key, wire)
	if err != nil || g.owner.ctx.Err() != nil {
		return
	}
	if registered {
		if p == nil && len(h.peers) >= maxAssociations {
			return
		}
		if p != nil {
			_ = p.packetInbox.Close()
		}
		delete(h.grants, s)
		p = &serverPackets{packetInbox: newPacketInbox(g.owner.ctx), hub: h, grant: g, peer: peer}
		h.peers[id] = p
		ctx := auth.ContextWithUser(p.ctx, g.owner.user.Name)
		go h.service.options.Handler.NewPacketConnectionEx(ctx, asPacketConn(p), M.SocksaddrFromNet(peer).Unwrap(), g.Destination, nil)
	}
	if !p.seen.accept(s) {
		return
	}
	p.lastActive = now
	select {
	case p.packets <- datagram{plain, g.Destination}:
	default:
	}
}

func (p *serverPackets) LocalAddr() net.Addr { return p.hub.transport.Conn.LocalAddr() }

func (p *serverPackets) Close() error {
	p.hub.mu.Lock()
	defer p.hub.mu.Unlock()
	if p.hub.peers[p.peer.String()] == p {
		delete(p.hub.peers, p.peer.String())
	}
	return p.packetInbox.Close()
}

func (p *serverPackets) WriteTo(b []byte, _ net.Addr) (int, error) {
	if err := p.writable(); err != nil {
		return 0, err
	}
	s, err := newSalt()
	if err != nil {
		return 0, err
	}
	if !p.seen.accept(s) {
		return 0, errSaltReuse
	}
	wire, err := sealPacket(p.grant.Key, s, b)
	if err != nil {
		return 0, err
	}
	if _, err = p.hub.transport.WriteTo(wire, p.peer); err != nil {
		return 0, err
	}
	p.hub.mu.Lock()
	p.lastActive = time.Now()
	p.hub.mu.Unlock()
	return len(b), nil
}
