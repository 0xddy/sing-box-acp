package anytls

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"

	"github.com/sagernet/sing-box/option"
	"golang.org/x/net/http/httpguts"
)

type identity struct {
	name string
	hash [sha256.Size]byte
}
type authentication struct {
	byHash     map[[sha256.Size]byte]identity
	authorized map[identity]struct{}
}

func (a *authentication) contains(user identity) bool { _, ok := a.authorized[user]; return ok }

// ValidateUsers checks a pending update without touching live sessions or web resources.
func ValidateUsers(users []option.AnyTLSUser) error {
	_, err := authenticationFor(users)
	return err
}

func authenticationFor(users []option.AnyTLSUser) (*authentication, error) {
	a := &authentication{authorized: make(map[identity]struct{}, len(users)), byHash: make(map[[sha256.Size]byte]identity, len(users))}
	names := make(map[string]struct{}, len(users))
	passwords := make(map[[sha256.Size]byte]struct{}, len(users))
	for _, user := range users {
		if user.Name == "" || user.Password == "" {
			return nil, fmt.Errorf("AnyTLS user name and password are required")
		}
		id := identity{user.Name, sha256.Sum256([]byte(user.Password))}
		if _, exists := names[id.name]; exists {
			return nil, fmt.Errorf("duplicate AnyTLS user name")
		}
		if _, exists := passwords[id.hash]; exists {
			return nil, fmt.Errorf("duplicate AnyTLS password")
		}
		names[id.name] = struct{}{}
		passwords[id.hash] = struct{}{}
		a.authorized[id] = struct{}{}
		a.byHash[id.hash] = id
	}
	return a, nil
}

// Recognize complete short HTTP request lines independently of credentials.
// Credential-dependent prefix rejection would expose an authentication oracle.
// All other connections are read through the complete fixed-size digest.
func identify(reader *bufio.Reader, users *authentication) (*identity, []byte, error) {
	prefix := make([]byte, 0, sha256.Size)
	for len(prefix) < sha256.Size {
		value, err := reader.ReadByte()
		if err != nil {
			return nil, prefix, err
		}
		prefix = append(prefix, value)
		if bytes.HasSuffix(prefix, []byte("\r\n")) && isHTTPRequestLine(string(prefix[:len(prefix)-2])) {
			return nil, prefix, nil
		}
	}
	var hash [sha256.Size]byte
	copy(hash[:], prefix)
	if user, ok := users.byHash[hash]; ok {
		return &user, prefix, nil
	}
	return nil, prefix, nil
}

func isHTTPRequestLine(line string) bool {
	method, rest, ok := strings.Cut(line, " ")
	if !ok || !httpguts.ValidHeaderFieldName(method) {
		return false
	}
	target, version, ok := strings.Cut(rest, " ")
	return ok && target != "" && (version == "HTTP/1.1" || version == "HTTP/1.0" || (method == "PRI" && target == "*" && version == "HTTP/2.0"))
}

func (h *Inbound) UpdateUsers(users []option.AnyTLSUser) error {
	replacement, err := authenticationFor(users)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.users = replacement
	var revoked []net.Conn
	for conn, user := range h.connections {
		if user != nil && !replacement.contains(*user) {
			revoked = append(revoked, conn)
		}
	}
	h.mu.Unlock()
	for _, conn := range revoked {
		h.closeConnection(conn)
	}
	return nil
}

func (h *Inbound) CloseUserSessions(userID string) int {
	h.mu.Lock()
	var connections []net.Conn
	for conn, user := range h.connections {
		if user != nil && user.name == userID {
			connections = append(connections, conn)
		}
	}
	h.mu.Unlock()
	for _, conn := range connections {
		h.closeConnection(conn)
	}
	return len(connections)
}
