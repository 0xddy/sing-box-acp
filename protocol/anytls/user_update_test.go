package anytls

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"testing/iotest"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestIdentifyFragmentsAndReplay(t *testing.T) {
	user := option.AnyTLSUser{Name: "1", Password: "password"}
	a, err := authenticationFor([]option.AnyTLSUser{user})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(user.Password))
	for _, payload := range [][]byte{digest[:], []byte("GET / HTTP/1.0\r\n\r\n"), []byte("BREW / HTTP/1.0\r\n\r\n"), []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")} {
		for _, fragment := range []bool{false, true} {
			var input io.Reader = bytes.NewReader(payload)
			if fragment {
				input = iotest.OneByteReader(input)
			}
			r := bufio.NewReader(input)
			id, prefix, err := identify(r, a)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(payload, digest[:]) {
				if id == nil || id.name != "1" {
					t.Fatal("fragmented authentication rejected")
				}
			} else {
				if id != nil {
					t.Fatal("HTTP authenticated")
				}
				rest, err := io.ReadAll(io.MultiReader(bytes.NewReader(prefix), r))
				if err != nil || !bytes.Equal(rest, payload) {
					t.Fatal("handoff lost bytes")
				}
			}
		}
	}
}

func TestUserRotationAndKickCloseIdleTransports(t *testing.T) {
	h := &Inbound{connections: make(map[net.Conn]*identity)}
	users := []option.AnyTLSUser{{Name: "1", Password: "first"}, {Name: "2", Password: "second"}}
	if err := h.UpdateUsers(users); err != nil {
		t.Fatal(err)
	}
	first, firstPeer := net.Pipe()
	defer first.Close()
	defer firstPeer.Close()
	second, secondPeer := net.Pipe()
	defer second.Close()
	defer secondPeer.Close()
	h.connections[first] = &identity{"1", sha256.Sum256([]byte("first"))}
	h.connections[second] = &identity{"2", sha256.Sum256([]byte("second"))}
	users[0].Password = "rotated"
	if err := h.UpdateUsers(users); err != nil {
		t.Fatal(err)
	}
	firstPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := firstPeer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("revoked idle transport survived", err)
	}
	secondPeer.SetReadDeadline(time.Now().Add(time.Millisecond))
	if _, err := secondPeer.Read(make([]byte, 1)); err == nil {
		t.Fatal("unexpected data on idle transport")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("unaffected transport closed during credential rotation", err)
	}
	secondPeer.SetReadDeadline(time.Time{})
	if n := h.CloseUserSessions("2"); n != 1 {
		t.Fatalf("closed %d sessions", n)
	}
	if _, err := secondPeer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal(err)
	}
	if err := h.UpdateUsers([]option.AnyTLSUser{{Name: "1", Password: "same"}, {Name: "2", Password: "same"}}); err == nil {
		t.Fatal("duplicate credentials accepted")
	}
	if !h.users.contains(identity{"1", sha256.Sum256([]byte("rotated"))}) {
		t.Fatal("invalid update mutated snapshot")
	}
}
