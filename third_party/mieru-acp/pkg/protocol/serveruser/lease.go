package serveruser

import (
	"io"
	"sync"
	"sync/atomic"
)

// A credential's lease survives unrelated table updates, but never deletion,
// password rotation or an explicit kick.
type lease struct {
	mu        sync.Mutex
	revoked   atomic.Bool
	resources map[io.Closer]bool // true for logical sessions, false for a TCP socket
}

func (p Policy) Active() bool { return p.lease == nil || !p.lease.revoked.Load() }

// SameCredential compares authenticated identities on a shared UDP socket.
func (p Policy) SameCredential(other Policy) bool {
	return p.Active() && p.lease == other.lease && p.name == other.name
}

// Attach serializes publication of a fully initialized session with revocation.
// A TCP socket stays registered even after its last session closes.
func (p Policy) Attach(session, socket io.Closer, start func() error) error {
	if p.lease == nil {
		return start()
	}
	l := p.lease
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revoked.Load() {
		return io.ErrClosedPipe
	}
	if err := start(); err != nil {
		return err
	}
	if l.resources == nil {
		l.resources = make(map[io.Closer]bool)
	}
	l.resources[session] = true
	if socket != nil {
		l.resources[socket] = false
	}
	return nil
}

func (p Policy) Forget(resource io.Closer) {
	if p.lease != nil {
		p.lease.mu.Lock()
		delete(p.lease.resources, resource)
		p.lease.mu.Unlock()
	}
}

func (l *lease) retire() map[io.Closer]bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.revoked.Store(true)
	resources := l.resources
	l.resources = nil
	return resources
}

func closeResources(resources map[io.Closer]bool) (count int) {
	for conn, session := range resources {
		if !session {
			_ = conn.Close()
		}
	}
	for conn, session := range resources {
		if session {
			_ = conn.Close()
			count++
		}
	}
	return
}

// Kick rotates a user's lease without changing the accepted credential.
func (r *Registry) Kick(name string) int {
	r.updateMu.Lock()
	old := r.users.Load()
	if old == nil {
		r.updateMu.Unlock()
		return 0
	}
	for i, u := range old.users {
		if u.name != name {
			continue
		}
		next := &state{users: append([]user(nil), old.users...), cache: newSourceUserCache(&r.stats)}
		next.users[i].policy.lease = new(lease)
		resources := u.policy.lease.retire()
		r.users.Store(next)
		old.cache.retire()
		r.updateMu.Unlock()
		return closeResources(resources)
	}
	r.updateMu.Unlock()
	return 0
}
