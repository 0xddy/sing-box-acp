package hysteria2

import "testing"

type testUserIdentity struct {
	user       string
	generation int
}

func TestUpdateUsersPublishesImmutableSnapshot(t *testing.T) {
	service := &Service[testUserIdentity]{sessions: make(map[managedSession[testUserIdentity]]struct{})}
	originalUser := testUserIdentity{user: "user-1", generation: 1}
	service.users.Store(newUserSnapshot(
		[]testUserIdentity{originalUser},
		[]string{"old-password"},
	))
	original := service.users.Load()

	updatedUser := testUserIdentity{user: "user-1", generation: 2}
	service.UpdateUsers(
		[]testUserIdentity{updatedUser},
		[]string{"new-password"},
	)

	if got, found := original.byPassword["old-password"]; !found || got != originalUser {
		t.Fatalf("original snapshot changed: user=%+v found=%t", got, found)
	}
	current := service.users.Load()
	if _, found := current.byPassword["old-password"]; found {
		t.Fatal("replacement snapshot retained old password")
	}
	if got := current.byPassword["new-password"]; got != updatedUser {
		t.Fatalf("replacement user = %+v, want %+v", got, updatedUser)
	}
}

func TestMatchingSessionsSelectsOnlyInvalidatedIdentity(t *testing.T) {
	service := &Service[testUserIdentity]{sessions: make(map[managedSession[testUserIdentity]]struct{})}
	oldUser1 := testUserIdentity{user: "user-1", generation: 1}
	newUser1 := testUserIdentity{user: "user-1", generation: 2}
	user2 := testUserIdentity{user: "user-2", generation: 1}
	user1Session := authenticatedTestSession(oldUser1)
	user2Session := authenticatedTestSession(user2)
	unauthenticated := &fakeManagedSession[testUserIdentity]{}
	service.sessions[user1Session] = struct{}{}
	service.sessions[user2Session] = struct{}{}
	service.sessions[unauthenticated] = struct{}{}

	replacement := newUserSnapshot(
		[]testUserIdentity{newUser1, user2},
		[]string{"new-user-1-password", "user-2-password"},
	)
	matched := service.matchingSessions(func(user testUserIdentity) bool {
		_, authorized := replacement.identities[user]
		return !authorized
	})

	if len(matched) != 1 || matched[0] != user1Session {
		t.Fatalf("matched session count = %d, want only the user-1 session", len(matched))
	}
}

func TestMatchingSessionsIgnoresUserReordering(t *testing.T) {
	service := &Service[testUserIdentity]{sessions: make(map[managedSession[testUserIdentity]]struct{})}
	user1 := testUserIdentity{user: "user-1", generation: 1}
	user2 := testUserIdentity{user: "user-2", generation: 1}
	service.sessions[authenticatedTestSession(user1)] = struct{}{}
	service.sessions[authenticatedTestSession(user2)] = struct{}{}

	reordered := newUserSnapshot(
		[]testUserIdentity{user2, user1},
		[]string{"user-2-password", "user-1-password"},
	)
	matched := service.matchingSessions(func(user testUserIdentity) bool {
		_, authorized := reordered.identities[user]
		return !authorized
	})
	if len(matched) != 0 {
		t.Fatalf("reordering invalidated %d sessions", len(matched))
	}
}

func TestUpdateUsersWithSessionRevocationClosesOnlyChangedCredential(t *testing.T) {
	service := &Service[testUserIdentity]{sessions: make(map[managedSession[testUserIdentity]]struct{})}
	oldUser1 := testUserIdentity{user: "user-1", generation: 1}
	newUser1 := testUserIdentity{user: "user-1", generation: 2}
	user2 := testUserIdentity{user: "user-2", generation: 1}
	user1Session := &fakeManagedSession[testUserIdentity]{identity: oldUser1, authenticated: true}
	user2Session := &fakeManagedSession[testUserIdentity]{identity: user2, authenticated: true}
	service.sessions[user1Session] = struct{}{}
	service.sessions[user2Session] = struct{}{}

	closed := service.UpdateUsersWithSessionRevocation(
		[]testUserIdentity{newUser1, user2},
		[]string{"new-user-1-password", "user-2-password"},
	)

	if closed != 1 || !user1Session.closed || user2Session.closed {
		t.Fatalf("closed=%d user1_closed=%t user2_closed=%t, want 1 true false", closed, user1Session.closed, user2Session.closed)
	}
}

func TestCloseSessionsDoesNotInvokeMatcherUnderRegistryLock(t *testing.T) {
	service := &Service[testUserIdentity]{sessions: make(map[managedSession[testUserIdentity]]struct{})}
	identity := testUserIdentity{user: "user-1", generation: 1}
	service.sessions[authenticatedTestSession(identity)] = struct{}{}

	closed := service.CloseSessions(func(testUserIdentity) bool {
		if nestedClosed := service.CloseSessions(func(testUserIdentity) bool { return false }); nestedClosed != 0 {
			t.Fatalf("nested close count = %d, want 0", nestedClosed)
		}
		return false
	})
	if closed != 0 {
		t.Fatalf("close count = %d, want 0", closed)
	}
}

func authenticatedTestSession(identity testUserIdentity) managedSession[testUserIdentity] {
	return &fakeManagedSession[testUserIdentity]{identity: identity, authenticated: true}
}

type fakeManagedSession[U comparable] struct {
	identity      U
	authenticated bool
	closed        bool
}

func (s *fakeManagedSession[U]) authenticatedIdentity() (U, bool) {
	return s.identity, s.authenticated
}

func (s *fakeManagedSession[U]) closeWithError(error) bool {
	if s.closed {
		return false
	}
	s.closed = true
	return true
}
