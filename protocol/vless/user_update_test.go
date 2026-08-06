package vless

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func TestUserIdentitiesAreStableSnapshots(t *testing.T) {
	users := []option.VLESSUser{
		{Name: "user-1", UUID: "11111111-1111-4111-8111-111111111111"},
		{Name: "user-2", UUID: "22222222-2222-4222-8222-222222222222"},
	}
	identities := userIdentities(users)
	original := identities[1]
	users[1].Name = "changed"
	users[1].UUID = "33333333-3333-4333-8333-333333333333"

	if len(identities) != 2 {
		t.Fatalf("identity count = %d, want 2", len(identities))
	}
	if identities[1] != original || identities[1].Name != "user-2" || identities[1].Index != 1 {
		t.Fatalf("identity = %+v, want the values captured at snapshot time", identities[1])
	}
}

func TestCredentialFingerprintCoversUUIDAndFlow(t *testing.T) {
	base := option.VLESSUser{Name: "user-1", UUID: "11111111-1111-4111-8111-111111111111"}
	rotatedUUID := base
	rotatedUUID.UUID = "99999999-9999-4999-8999-999999999999"
	changedFlow := base
	changedFlow.Flow = "xtls-rprx-vision"
	// sing-vmess normalizes the configured UUID before using it as a lookup
	// key, so equivalent spellings must produce one identity.
	upperCase := base
	upperCase.UUID = strings.ToUpper(base.UUID)

	original := userIdentities([]option.VLESSUser{base})[0]
	for name, other := range map[string]option.VLESSUser{
		"rotated uuid": rotatedUUID,
		"changed flow": changedFlow,
	} {
		if original.credential() == userIdentities([]option.VLESSUser{other})[0].credential() {
			t.Fatalf("%s reused the previous credential identity", name)
		}
	}
	if original.credential() != userIdentities([]option.VLESSUser{upperCase})[0].credential() {
		t.Fatal("an equivalent UUID spelling produced a different credential identity")
	}
}

func TestReorderingDoesNotChangeCredentialIdentity(t *testing.T) {
	user1 := option.VLESSUser{Name: "user-1", UUID: "11111111-1111-4111-8111-111111111111"}
	user2 := option.VLESSUser{Name: "user-2", UUID: "22222222-2222-4222-8222-222222222222"}
	original := userIdentities([]option.VLESSUser{user1, user2})
	reordered := userIdentities([]option.VLESSUser{user2, user1})

	if original[0].credential() != reordered[1].credential() {
		t.Fatal("reordering changed the credential identity")
	}
}

func TestDuplicateUUIDIsRejected(t *testing.T) {
	inbound := testInbound(t, option.VLESSUser{Name: "user-1", UUID: "11111111-1111-4111-8111-111111111111"})
	before := inbound.auth.Load()

	err := inbound.UpdateUsers([]option.VLESSUser{
		{Name: "user-1", UUID: "11111111-1111-4111-8111-111111111111"},
		{Name: "user-2", UUID: strings.ToUpper("11111111-1111-4111-8111-111111111111")},
	})
	if err == nil {
		t.Fatal("duplicate UUID was accepted")
	}
	if !strings.Contains(err.Error(), "duplicate UUID") {
		t.Fatalf("error = %v, want a duplicate UUID rejection", err)
	}
	if inbound.auth.Load() != before {
		t.Fatal("rejected user list replaced the running authentication table")
	}
}

func TestAuthorizeConnectionRejectsIdentityRevokedDuringHandshake(t *testing.T) {
	user1 := option.VLESSUser{Name: "user-1", UUID: "11111111-1111-4111-8111-111111111111"}
	user2 := option.VLESSUser{Name: "user-2", UUID: "22222222-2222-4222-8222-222222222222"}
	inbound := testInbound(t, user1, user2)
	handshaking := userIdentities([]option.VLESSUser{user1})[0]
	unaffected := userIdentities([]option.VLESSUser{user2})[0]

	// The credential is rotated while the handshake is still in flight, so the
	// connection authenticated against the previous snapshot must not be routed.
	if err := inbound.UpdateUsers([]option.VLESSUser{
		{Name: "user-1", UUID: "99999999-9999-4999-8999-999999999999"},
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

func TestAuthorizeConnectionSurvivesUserListChangesThatKeepTheCredential(t *testing.T) {
	user1 := option.VLESSUser{Name: "user-1", UUID: "11111111-1111-4111-8111-111111111111"}
	user2 := option.VLESSUser{Name: "user-2", UUID: "22222222-2222-4222-8222-222222222222"}
	added := option.VLESSUser{Name: "user-3", UUID: "33333333-3333-4333-8333-333333333333"}
	established := userIdentities([]option.VLESSUser{user1})[0]

	for name, replacement := range map[string][]option.VLESSUser{
		"reordered": {user2, user1},
		"added":     {user1, user2, added},
		"removed":   {user1},
	} {
		t.Run(name, func(t *testing.T) {
			inbound := testInbound(t, user1, user2)
			if err := inbound.UpdateUsers(replacement); err != nil {
				t.Fatalf("update users: %v", err)
			}
			if _, _, err := inbound.authorizeConnection(testUserContext(established), &testCloser{}); err != nil {
				t.Fatalf("established identity was revoked: %v", err)
			}
		})
	}
}

// A connection that has been authorized but has not reached the router yet is
// invisible to the traffic tracker, so the inbound itself has to close it.
func TestUpdateUsersClosesRegisteredConnectionsOfRotatedCredential(t *testing.T) {
	user1 := option.VLESSUser{Name: "user-1", UUID: "11111111-1111-4111-8111-111111111111"}
	user2 := option.VLESSUser{Name: "user-2", UUID: "22222222-2222-4222-8222-222222222222"}
	inbound := testInbound(t, user1, user2)

	rotating := &testCloser{}
	if _, _, err := inbound.authorizeConnection(testUserContext(userIdentities([]option.VLESSUser{user1})[0]), rotating); err != nil {
		t.Fatalf("authorize rotating user: %v", err)
	}
	stable := &testCloser{}
	if _, _, err := inbound.authorizeConnection(testUserContext(userIdentities([]option.VLESSUser{user2})[0]), stable); err != nil {
		t.Fatalf("authorize stable user: %v", err)
	}

	if err := inbound.UpdateUsers([]option.VLESSUser{
		{Name: "user-1", UUID: "99999999-9999-4999-8999-999999999999"},
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
	user1 := option.VLESSUser{Name: "user-1", UUID: "11111111-1111-4111-8111-111111111111"}
	user2 := option.VLESSUser{Name: "user-2", UUID: "22222222-2222-4222-8222-222222222222"}
	inbound := testInbound(t, user1, user2)

	kicked := &testCloser{}
	if _, _, err := inbound.authorizeConnection(testUserContext(userIdentities([]option.VLESSUser{user1})[0]), kicked); err != nil {
		t.Fatalf("authorize kicked user: %v", err)
	}
	other := &testCloser{}
	if _, _, err := inbound.authorizeConnection(testUserContext(userIdentities([]option.VLESSUser{user2})[0]), other); err != nil {
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
	if _, _, err := inbound.authorizeConnection(testUserContext(userIdentities([]option.VLESSUser{user1})[0]), reconnected); err != nil {
		t.Fatalf("reconnect after kick was rejected: %v", err)
	}
	if reconnected.isClosed() {
		t.Fatal("reconnect after kick was closed")
	}
}

// A flow change invalidates the authentication parameters, so a handshake still
// inside the hand-off window must not complete under the previous flow. Sessions
// the router already handed to its trackers are outside the window and keep the
// flow they were established with until they close.
func TestFlowChangeRejectsHandshakesStillInTheHandoffWindow(t *testing.T) {
	user := option.VLESSUser{Name: "user-1", UUID: "11111111-1111-4111-8111-111111111111"}
	inbound := testInbound(t, user)
	handshaking := &testCloser{}
	identity := userIdentities([]option.VLESSUser{user})[0]
	if _, _, err := inbound.authorizeConnection(testUserContext(identity), handshaking); err != nil {
		t.Fatalf("authorize user: %v", err)
	}

	changedFlow := user
	changedFlow.Flow = "xtls-rprx-vision"
	if err := inbound.UpdateUsers([]option.VLESSUser{changedFlow}); err != nil {
		t.Fatalf("update users: %v", err)
	}

	if !handshaking.isClosed() {
		t.Fatal("flow change left a handshake running under the previous flow")
	}
	if _, _, err := inbound.authorizeConnection(testUserContext(identity), &testCloser{}); err != os.ErrPermission {
		t.Fatalf("stale flow identity error = %v, want %v", err, os.ErrPermission)
	}
}

// The registry has to stay populated for the whole call into the router,
// because the router registers the connection with its trackers before it
// returns. Unregistering any earlier would leave a moment where nobody can
// close the connection; keeping the entry after the call would duplicate the
// tracker that now owns it.
func TestRegistrationSpansTheCallIntoTheRouter(t *testing.T) {
	user := option.VLESSUser{Name: "user-1", UUID: "11111111-1111-4111-8111-111111111111"}
	inbound := testInbound(t, user)
	router := &recordingRouter{inbound: inbound}
	inbound.router = router

	inbound.newConnectionEx(
		testUserContext(userIdentities([]option.VLESSUser{user})[0]),
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
	stable := option.VLESSUser{Name: "stable", UUID: "22222222-2222-4222-8222-222222222222"}
	inbound := testInbound(t, stable)
	stableIdentity := userIdentities([]option.VLESSUser{stable})[0]

	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for i := 0; i < 500; i++ {
			if err := inbound.UpdateUsers([]option.VLESSUser{
				stable,
				{Name: "rotating", UUID: fmt.Sprintf("11111111-1111-4111-8111-%012d", i)},
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

func testInbound(t *testing.T, users ...option.VLESSUser) *Inbound {
	t.Helper()
	inbound := &Inbound{logger: logger.NOP()}
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
