package trojan

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	N "github.com/sagernet/sing/common/network"
)

func TestCredentialRotationChangesIdentityButReorderingDoesNot(t *testing.T) {
	user1 := option.TrojanUser{Name: "user-1", Password: "password-1"}
	user2 := option.TrojanUser{Name: "user-2", Password: "password-2"}
	original := userIdentities([]option.TrojanUser{user1, user2})
	reordered := userIdentities([]option.TrojanUser{user2, user1})
	rotated := userIdentities([]option.TrojanUser{{Name: "user-1", Password: "password-1-rotated"}})

	if original[0].credential() != reordered[1].credential() {
		t.Fatal("reordering changed the credential identity")
	}
	if original[0].credential() == rotated[0].credential() {
		t.Fatal("password rotation reused the previous credential identity")
	}
}

func TestAuthorizeConnectionRejectsIdentityRevokedDuringHandshake(t *testing.T) {
	user1 := option.TrojanUser{Name: "user-1", Password: "password-1"}
	user2 := option.TrojanUser{Name: "user-2", Password: "password-2"}
	inbound := testInbound(t, user1, user2)
	handshaking := userIdentities([]option.TrojanUser{user1})[0]
	unaffected := userIdentities([]option.TrojanUser{user2})[0]

	// The password is rotated while the handshake is still in flight, so the
	// connection authenticated against the previous snapshot must not be routed.
	if err := inbound.UpdateUsers([]option.TrojanUser{
		{Name: "user-1", Password: "password-1-rotated"},
		user2,
	}); err != nil {
		t.Fatalf("update users: %v", err)
	}

	if _, _, err := inbound.authorizeConnection(testUserContext(handshaking), &testCloser{}); err != os.ErrPermission {
		t.Fatalf("revoked identity error = %v, want %v", err, os.ErrPermission)
	}
	if _, _, err := inbound.authorizeConnection(testUserContext(unaffected), &testCloser{}); err != nil {
		t.Fatalf("unaffected user was rejected: %v", err)
	}
}

// A connection that has been authorized but has not reached the router yet is
// invisible to the traffic tracker, so the inbound itself has to close it.
func TestUpdateUsersClosesRegisteredConnectionsOfRotatedCredential(t *testing.T) {
	user1 := option.TrojanUser{Name: "user-1", Password: "password-1"}
	user2 := option.TrojanUser{Name: "user-2", Password: "password-2"}
	inbound := testInbound(t, user1, user2)

	rotating := &testCloser{}
	if _, _, err := inbound.authorizeConnection(testUserContext(userIdentities([]option.TrojanUser{user1})[0]), rotating); err != nil {
		t.Fatalf("authorize rotating user: %v", err)
	}
	stable := &testCloser{}
	if _, _, err := inbound.authorizeConnection(testUserContext(userIdentities([]option.TrojanUser{user2})[0]), stable); err != nil {
		t.Fatalf("authorize stable user: %v", err)
	}

	if err := inbound.UpdateUsers([]option.TrojanUser{
		{Name: "user-1", Password: "password-1-rotated"},
		user2,
	}); err != nil {
		t.Fatalf("update users: %v", err)
	}
	if !rotating.isClosed() {
		t.Fatal("connection of the rotated credential was left running")
	}
	if stable.isClosed() {
		t.Fatal("connection of an unaffected user was closed")
	}
}

// A kick keeps the user authorized, so the credential is unchanged and
// UpdateUsers would not touch anything. The tracker cannot close what the
// router has not handed it yet, and it cannot tell a connection authenticated
// before the kick from one authenticated after it, so the inbound has to drop
// its hand-off window explicitly.
func TestCloseUserSessionsDropsTheHandoffWindowOfOneUser(t *testing.T) {
	user1 := option.TrojanUser{Name: "user-1", Password: "password-1"}
	user2 := option.TrojanUser{Name: "user-2", Password: "password-2"}
	inbound := testInbound(t, user1, user2)

	kicked := &testCloser{}
	if _, _, err := inbound.authorizeConnection(testUserContext(userIdentities([]option.TrojanUser{user1})[0]), kicked); err != nil {
		t.Fatalf("authorize kicked user: %v", err)
	}
	other := &testCloser{}
	if _, _, err := inbound.authorizeConnection(testUserContext(userIdentities([]option.TrojanUser{user2})[0]), other); err != nil {
		t.Fatalf("authorize other user: %v", err)
	}

	if closed := inbound.CloseUserSessions("user-1"); closed != 1 {
		t.Fatalf("closed sessions = %d, want 1", closed)
	}
	if !kicked.isClosed() {
		t.Fatal("kicked user kept a connection in the hand-off window")
	}
	if other.isClosed() {
		t.Fatal("kick closed another user's connection")
	}

	// The user stays authorized, so a connection authenticated after the kick
	// must be admitted immediately.
	reconnected := &testCloser{}
	if _, _, err := inbound.authorizeConnection(testUserContext(userIdentities([]option.TrojanUser{user1})[0]), reconnected); err != nil {
		t.Fatalf("reconnect after kick was rejected: %v", err)
	}
	if reconnected.isClosed() {
		t.Fatal("reconnect after kick was closed")
	}
}

// A shrinking user list used to be the worst case: the user slice was replaced
// before the authentication table, so a handshake that had already resolved a
// high index panicked while reading the display name.
func TestShrinkingUserListDoesNotBreakInFlightHandshake(t *testing.T) {
	users := []option.TrojanUser{
		{Name: "user-1", Password: "password-1"},
		{Name: "user-2", Password: "password-2"},
		{Name: "user-3", Password: "password-3"},
	}
	inbound := testInbound(t, users...)
	handshaking := userIdentities(users)[2]

	if err := inbound.UpdateUsers(users[:1]); err != nil {
		t.Fatalf("update users: %v", err)
	}
	if _, _, err := inbound.authorizeConnection(testUserContext(handshaking), &testCloser{}); err != os.ErrPermission {
		t.Fatalf("removed identity error = %v, want %v", err, os.ErrPermission)
	}
}

func TestRejectedUserListLeavesAuthenticationTableUntouched(t *testing.T) {
	user1 := option.TrojanUser{Name: "user-1", Password: "password-1"}
	inbound := testInbound(t, user1)
	before := inbound.auth.Load()

	duplicate := []option.TrojanUser{user1, {Name: "user-2", Password: "password-1"}}
	if err := inbound.UpdateUsers(duplicate); err == nil {
		t.Fatal("duplicate password was accepted")
	}
	if inbound.auth.Load() != before {
		t.Fatal("rejected user list replaced the running authentication table")
	}
	if _, _, err := inbound.authorizeConnection(testUserContext(userIdentities([]option.TrojanUser{user1})[0]), &testCloser{}); err != nil {
		t.Fatalf("existing user was revoked by a rejected update: %v", err)
	}
}

// The registry has to stay populated for the whole call into the router,
// because the router registers the connection with its trackers before it
// returns. Unregistering any earlier would leave a moment where nobody can
// close the connection; keeping the entry after the call would duplicate the
// tracker that now owns it.
func TestRegistrationSpansTheCallIntoTheRouter(t *testing.T) {
	user := option.TrojanUser{Name: "user-1", Password: "password-1"}
	inbound := testInbound(t, user)
	router := &recordingRouter{inbound: inbound}
	inbound.router = router

	inbound.newConnection(
		testUserContext(userIdentities([]option.TrojanUser{user})[0]),
		&testCloser{},
		adapter.InboundContext{},
		nil,
	)

	if !router.routed {
		t.Fatal("connection was not routed")
	}
	if router.registeredDuringRouting != 1 {
		t.Fatalf("registered connections while routing = %d, want 1", router.registeredDuringRouting)
	}
	if remaining := inbound.connections.count(); remaining != 0 {
		t.Fatalf("registry holds %d connections after routing returned, want 0", remaining)
	}
}

func (r *connectionRegistry) count() int {
	r.access.Lock()
	defer r.access.Unlock()
	return len(r.connections)
}

type recordingRouter struct {
	routed                  bool
	registeredDuringRouting int
	inbound                 *Inbound
}

func (r *recordingRouter) RouteConnectionEx(_ context.Context, _ net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.routed = true
	r.registeredDuringRouting = r.inbound.connections.count()
}

func (r *recordingRouter) RoutePacketConnectionEx(context.Context, N.PacketConn, adapter.InboundContext, N.CloseHandlerFunc) {
}

func (r *recordingRouter) RouteConnection(context.Context, net.Conn, adapter.InboundContext) error {
	return nil
}

func (r *recordingRouter) RoutePacketConnection(context.Context, N.PacketConn, adapter.InboundContext) error {
	return nil
}

func TestConcurrentUserUpdatesAndAuthorizationChecks(t *testing.T) {
	stable := option.TrojanUser{Name: "stable", Password: "stable-password"}
	inbound := testInbound(t, stable)
	stableIdentity := userIdentities([]option.TrojanUser{stable})[0]

	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for i := 0; i < 500; i++ {
			if err := inbound.UpdateUsers([]option.TrojanUser{
				stable,
				{Name: "rotating", Password: fmt.Sprintf("rotating-password-%d", i)},
			}); err != nil {
				t.Errorf("update users: %v", err)
				return
			}
		}
	}()
	go func() {
		defer wait.Done()
		ctx := testUserContext(stableIdentity)
		for i := 0; i < 500; i++ {
			_, registered, err := inbound.authorizeConnection(ctx, &testCloser{})
			if err != nil {
				t.Errorf("stable user rejected during concurrent update: %v", err)
				return
			}
			inbound.connections.remove(registered)
		}
	}()
	wait.Wait()
}

func testInbound(t *testing.T, users ...option.TrojanUser) *Inbound {
	t.Helper()
	inbound := &Inbound{logger: log.NewNOPFactory().NewLogger("test")}
	initial, err := inbound.authenticatorForUsers(users)
	if err != nil {
		t.Fatalf("build authenticator: %v", err)
	}
	inbound.auth.Store(initial)
	return inbound
}

func testUserContext(identity userIdentity) context.Context {
	return auth.ContextWithUser(context.Background(), identity)
}

type testCloser struct {
	access sync.Mutex
	closed bool
}

func (c *testCloser) Close() error {
	c.access.Lock()
	defer c.access.Unlock()
	c.closed = true
	return nil
}

func (c *testCloser) isClosed() bool {
	c.access.Lock()
	defer c.access.Unlock()
	return c.closed
}

// The registry stores connections as io.Closer, but the handler signature needs
// a net.Conn, so the stub satisfies both.
var _ net.Conn = (*testCloser)(nil)

func (c *testCloser) Read([]byte) (int, error)         { return 0, os.ErrClosed }
func (c *testCloser) Write([]byte) (int, error)        { return 0, os.ErrClosed }
func (c *testCloser) LocalAddr() net.Addr              { return nil }
func (c *testCloser) RemoteAddr() net.Addr             { return nil }
func (c *testCloser) SetDeadline(time.Time) error      { return nil }
func (c *testCloser) SetReadDeadline(time.Time) error  { return nil }
func (c *testCloser) SetWriteDeadline(time.Time) error { return nil }
