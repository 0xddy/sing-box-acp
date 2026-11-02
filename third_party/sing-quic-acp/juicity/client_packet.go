package juicity

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Stream UDP shares one stream across destinations. Underlay has no per-packet
// address field and therefore needs its own data socket for each destination.
type clientPackets struct {
	*packetInbox
	client   *Client
	mu       sync.Mutex
	paths    map[M.Socksaddr]net.PacketConn
	deadline time.Time
}

func (c *Client) ListenPacket(ctx context.Context, _ M.Socksaddr) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	epoch := c.epoch
	c.mu.Unlock()
	p := &clientPackets{packetInbox: newPacketInbox(epoch), client: c, paths: make(map[M.Socksaddr]net.PacketConn)}
	if epoch.Err() != nil {
		_ = p.Close()
		return nil, net.ErrClosed
	}
	return asPacketConn(p), nil
}

func (p *clientPackets) path(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	if err := p.writable(); err != nil {
		return nil, err
	}
	if !dst.IsValid() {
		return nil, errors.New("missing Juicity UDP destination")
	}
	underlay := p.client.options.UDPMode == "underlay"
	var pathKey M.Socksaddr
	if underlay {
		pathKey = dst
	}
	if c := p.paths[pathKey]; c != nil {
		peer, ok := c.(*underlayPath)
		if !ok || !peer.renew() {
			return c, nil
		}
		delete(p.paths, pathKey)
		_ = peer.Close()
	}
	if len(p.paths) >= maxAssociations {
		for dst, c := range p.paths {
			if peer, ok := c.(*underlayPath); ok && peer.renew() {
				delete(p.paths, dst)
				_ = peer.Close()
			}
		}
		if len(p.paths) >= maxAssociations {
			return nil, errors.New("too many Juicity UDP destinations")
		}
	}
	var path net.PacketConn
	var err error
	if underlay {
		path, err = p.client.openUnderlay(ctx, dst)
	} else {
		var conn *streamConn
		conn, err = p.client.openStream(ctx, networkUDP, dst)
		if err == nil {
			path = &streamPackets{streamConn: conn}
		}
	}
	if err != nil {
		return nil, err
	}
	_ = path.SetWriteDeadline(p.deadline)
	p.paths[pathKey] = path
	go p.readPath(pathKey, path)
	return path, nil
}

func (p *clientPackets) readPath(key M.Socksaddr, path net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, src, err := path.ReadFrom(buf)
		if err != nil {
			p.mu.Lock()
			current := p.paths[key] == path
			last := current && len(p.paths) == 1
			if current && !last {
				delete(p.paths, key)
			}
			if last {
				p.cancel()
			}
			p.mu.Unlock()
			if last {
				_ = p.Close()
			} else if current {
				_ = path.Close()
			}
			return
		}
		pkt := datagram{append([]byte(nil), buf[:n]...), M.SocksaddrFromNet(src)}
		select {
		case p.packets <- pkt:
		case <-p.ctx.Done():
			return
		}
	}
}

func (p *clientPackets) WriteTo(b []byte, a net.Addr) (int, error) {
	dst := M.SocksaddrFromNet(a).Unwrap()
	p.mu.Lock()
	path, err := p.path(p.ctx, dst)
	p.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return path.WriteTo(b, dst)
}

func (p *clientPackets) Close() error {
	_ = p.packetInbox.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, path := range p.paths {
		delete(p.paths, k)
		_ = path.Close()
	}
	return nil
}

func (p *clientPackets) LocalAddr() net.Addr { return M.Socksaddr{} }

func (p *clientPackets) SetWriteDeadline(t time.Time) error {
	p.writeDeadline.Set(t)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deadline = t
	for _, c := range p.paths {
		_ = c.SetWriteDeadline(t)
	}
	return nil
}

func (p *clientPackets) SetDeadline(t time.Time) error {
	_ = p.SetReadDeadline(t)
	return p.SetWriteDeadline(t)
}

type underlayPath struct {
	net.Conn
	destination M.Socksaddr
	key         key
	first       *salt
	writeMu     sync.Mutex
	seen        saltWindow
	stop        func() bool
	release     func()
	once        sync.Once
	lastReply   atomic.Int64
	packets     atomic.Uint32
	created     time.Time
}

func (p *underlayPath) renew() bool {
	if p.packets.Load() >= saltsPerKey/2 {
		return true
	}
	if last := p.lastReply.Load(); last != 0 {
		return time.Since(time.Unix(0, last)) >= defaultUDPTimeout/2
	}
	return time.Since(p.created) >= defaultAuthTimeout
}

func (c *Client) openUnderlay(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	r, err := newRegistration(dst)
	if err != nil {
		return nil, err
	}
	owner, err := c.acquire(ctx, false)
	if err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(owner.conn.Context(), cancel)
	raw, err := c.options.Dialer.DialContext(dialCtx, N.NetworkUDP, c.options.ServerAddress)
	stop()
	cancel()
	if err != nil {
		c.release(owner)
		return nil, err
	}
	err = owner.register(ctx, r)
	if err != nil {
		_ = raw.Close()
		c.release(owner)
		return nil, err
	}
	path := &underlayPath{Conn: raw, destination: dst, key: r.Key, first: &r.Salt, created: time.Now(), release: func() { c.release(owner) }}
	path.stop = context.AfterFunc(owner.conn.Context(), func() { _ = raw.Close() })
	return path, nil
}

func (s *clientSession) register(ctx context.Context, r registration) error {
	if wait := time.Until(s.firstRegistration); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.conn.Context().Done():
			return net.ErrClosed
		case <-timer.C:
		}
	}
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	_ = s.control.SetWriteDeadline(time.Now().Add(defaultAuthTimeout))
	err := r.write(s.control)
	_ = s.control.SetWriteDeadline(time.Time{})
	if err != nil {
		s.shutdown()
	}
	return err
}

func (p *underlayPath) Close() error {
	p.once.Do(func() { p.stop(); _ = p.Conn.Close(); p.release() })
	return nil
}

func (p *underlayPath) WriteTo(b []byte, a net.Addr) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if M.SocksaddrFromNet(a).Unwrap() != p.destination {
		return 0, net.ErrWriteToConnected
	}
	var s salt
	var err error
	if p.first != nil {
		s = *p.first
	} else {
		s, err = newSalt()
		if err != nil {
			return 0, err
		}
	}
	if !p.seen.accept(s) {
		return 0, errSaltReuse
	}
	wire, err := sealPacket(p.key, s, b)
	if err != nil {
		return 0, err
	}
	if _, err = p.Conn.Write(wire); err != nil {
		// The socket may have emitted the packet. A fresh key avoids nonce reuse on retry.
		p.packets.Store(saltsPerKey)
		return 0, err
	}
	p.first = nil
	p.packets.Add(1)
	return len(b), nil
}

func (p *underlayPath) ReadFrom(b []byte) (int, net.Addr, error) {
	wire := b
	if len(wire) < 65535 {
		wire = make([]byte, 65535)
	}
	for {
		n, err := p.Conn.Read(wire)
		if err != nil {
			return 0, nil, err
		}
		s, plain, err := openPacket(p.key, wire[:n])
		if err != nil || !p.seen.accept(s) {
			continue
		}
		p.lastReply.Store(time.Now().UnixNano())
		p.packets.Add(1)
		return copy(b, plain), p.destination, nil
	}
}
