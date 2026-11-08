package naive

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"sync"

	"github.com/sagernet/sing/common/auth"
)

type userIdentity struct {
	name     string
	password [32]byte
}

func authenticationFor(users []auth.User) (map[string]userIdentity, error) {
	result := make(map[string]userIdentity, len(users))
	for _, u := range users {
		if u.Username == "" || u.Password == "" {
			return nil, fmt.Errorf("Naive username and password are required")
		}
		if _, exists := result[u.Username]; exists {
			return nil, fmt.Errorf("duplicate Naive username")
		}
		result[u.Username] = userIdentity{u.Username, sha256.Sum256([]byte(u.Password))}
	}
	return result, nil
}
func ValidateUsers(users []auth.User) error { _, err := authenticationFor(users); return err }

func (n *Inbound) ValidateUsers(users []auth.User) error { return ValidateUsers(users) }

func (n *Inbound) UpdateUsers(users []auth.User) error {
	replacement, err := authenticationFor(users)
	if err != nil {
		return err
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return net.ErrClosed
	}
	n.users = replacement
	var revoked []*userFlow
	for flow, identity := range n.flows {
		if current, ok := replacement[identity.name]; !ok || current != identity {
			revoked = append(revoked, flow)
		}
	}
	n.mu.Unlock()
	for _, flow := range revoked {
		_ = flow.abort()
	}
	return nil
}
func (n *Inbound) CloseUserSessions(userID string) int {
	n.mu.Lock()
	var revoked []*userFlow
	for flow, identity := range n.flows {
		if identity.name == userID {
			revoked = append(revoked, flow)
		}
	}
	n.mu.Unlock()
	for _, flow := range revoked {
		_ = flow.abort()
	}
	return len(revoked)
}

// Authentication and registration share the update lock. A revoke therefore
// includes every earlier authentication, even before its transport is attached.
func (n *Inbound) beginFlow(ctx context.Context, username, password string) (*userFlow, bool) {
	hash := sha256.Sum256([]byte(password))
	n.mu.Lock()
	defer n.mu.Unlock()
	identity, ok := n.users[username]
	matches := subtle.ConstantTimeCompare(hash[:], identity.password[:]) == 1
	if !ok || !matches || n.closed {
		return nil, false
	}
	if len(n.flows) >= maxAuthenticatedFlows {
		return nil, true
	}
	ctx, cancel := context.WithCancel(ctx)
	flow := &userFlow{ctx: ctx, cancel: cancel}
	n.flows[flow] = identity
	return flow, true
}
func (n *Inbound) endFlow(flow *userFlow) { n.mu.Lock(); delete(n.flows, flow); n.mu.Unlock() }

type userFlow struct {
	net.Conn
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	once   sync.Once
}

func (f *userFlow) attach(conn net.Conn) bool {
	f.mu.Lock()
	if f.closed || f.ctx.Err() != nil {
		f.mu.Unlock()
		_ = conn.Close()
		return false
	}
	f.Conn = conn
	f.mu.Unlock()
	return true
}
func (f *userFlow) Close() error {
	return f.close(false)
}
func (f *userFlow) abort() error { return f.close(true) }
func (f *userFlow) close(abort bool) error {
	f.once.Do(func() {
		f.mu.Lock()
		f.closed = true
		conn := f.Conn
		f.mu.Unlock()
		f.cancel()
		if conn != nil {
			if stream, ok := conn.(interface{ abort() error }); ok && abort {
				_ = stream.abort()
			} else {
				_ = conn.Close()
			}
		}
	})
	return nil
}
