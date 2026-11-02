package protocol

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"google.golang.org/protobuf/proto"
)

func account(name, password string) *pb.User {
	return &pb.User{Name: proto.String(name), Password: proto.String(password)}
}

type echoMux struct {
	server *Mux
	remote UnderlayProperties
}

func startEchoMux(t *testing.T, packet bool) *echoMux {
	t.Helper()
	var addr net.Addr
	transport := common.StreamTransport
	port, err := common.UnusedTCPPort()
	if packet {
		port, err = common.UnusedUDPPort()
		transport = common.PacketTransport
		addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	} else {
		addr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	}
	if err != nil {
		t.Fatal(err)
	}
	mux := NewMux(false).SetEndpoints([]UnderlayProperties{NewUnderlayProperties(1400, transport, addr, nil)})
	if err := mux.StartEmpty(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	go func() {
		for {
			c, err := mux.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) }(c)
		}
	}()
	return &echoMux{mux, NewUnderlayProperties(1400, transport, nil, addr)}
}

func (e *echoMux) client(t *testing.T, name, password string) *Mux {
	t.Helper()
	mux := NewMux(true).SetClientUserNamePassword(name, cipher.HashPassword([]byte(password), []byte(name))).SetClientMultiplexFactor(3).SetEndpoints([]UnderlayProperties{e.remote})
	t.Cleanup(func() { mux.Close() })
	return mux
}

// Keep the authenticated socket as the only transport on which a client
// can open a new logical session. A rejected redial is not an auth result.
type singleSocket struct{ opened atomic.Bool }

func (s *singleSocket) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !s.opened.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("test: second TCP socket disabled")
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}
func (s *singleSocket) ListenPacket(ctx context.Context, network, laddr, _ string) (net.PacketConn, error) {
	if !s.opened.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("test: second UDP socket disabled")
	}
	return (&net.ListenConfig{}).ListenPacket(ctx, network, laddr)
}

// The upstream scheduler occasionally requests a new socket even when a
// reusable one exists. Retry that choice without permitting another socket.
func onExistingSocket(mux *Mux) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var c net.Conn
	var err error
	for i := 0; i < 32; i++ {
		c, err = mux.DialContext(ctx)
		if err == nil {
			return c, nil
		}
	}
	return nil, err
}

func openEcho(t *testing.T, mux *Mux) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	c, err := mux.DialContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := exchange(c); err != nil {
		t.Fatal(err)
	}
	return c
}
func exchange(c net.Conn) error {
	c.SetDeadline(time.Now().Add(700 * time.Millisecond))
	if _, err := c.Write([]byte{'x'}); err != nil {
		return err
	}
	var response [1]byte
	if _, err := io.ReadFull(c, response[:]); err != nil {
		return err
	}
	if response[0] != 'x' {
		return fmt.Errorf("wrong payload %q", response)
	}
	return nil
}

func TestCredentialRevocation(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, action := range []string{"delete", "rotate", "kick", "delete-readd"} {
			t.Run(network+"/"+action, func(t *testing.T) {
				e := startEchoMux(t, network == "udp")
				table := map[string]*pb.User{"alice": account("alice", "old"), "bob": account("bob", "stable")}
				e.server.SetServerUsers(table)
				alice := e.client(t, "alice", "old")
				socket := new(singleSocket)
				alice.SetDialer(socket).SetPacketDialer(socket)
				a := openEcho(t, alice)
				second, err := onExistingSocket(alice)
				if err != nil {
					t.Fatal(err)
				}
				if err = exchange(second); err != nil {
					t.Fatalf("second logical session on original socket: %v", err)
				}
				defer second.Close()
				defer a.Close()
				b := openEcho(t, e.client(t, "bob", "stable"))
				defer b.Close()
				table["carol"] = account("carol", "third")
				e.server.SetServerUsers(table)
				if err := exchange(a); err != nil {
					t.Fatalf("unrelated addition interrupted Alice: %v", err)
				}
				// Race session registration on Alice's authenticated transport with revocation.
				pending := make(chan net.Conn, 1)
				go func() {
					c, _ := onExistingSocket(alice)
					if c != nil {
						_ = exchange(c)
					}
					pending <- c
				}()
				switch action {
				case "kick":
					if n := e.server.CloseUserSessions("alice"); n < 1 {
						t.Fatalf("closed %d sessions", n)
					}
				case "rotate":
					table["alice"] = account("alice", "new")
					e.server.SetServerUsers(table)
				default:
					delete(table, "alice")
					e.server.SetServerUsers(table)
				}
				if err := exchange(a); err == nil {
					t.Fatal("revoked session still carries traffic")
				}
				if c := <-pending; c != nil {
					defer c.Close()
					if action != "kick" && exchange(c) == nil {
						t.Fatal("concurrent session survived revocation")
					}
				}
				if err := exchange(b); err != nil {
					t.Fatalf("Bob was interrupted: %v", err)
				}
				if action != "kick" {
					if c, err := onExistingSocket(alice); err == nil {
						defer c.Close()
						if exchange(c) == nil {
							t.Fatal("old credential opened a stream")
						}
					}
				}
				if action == "delete" {
					return
				}
				password := "old"
				if action == "rotate" {
					password = "new"
				}
				if action == "delete-readd" {
					table["alice"] = account("alice", "old")
					e.server.SetServerUsers(table)
					if exchange(a) == nil {
						t.Fatal("old session revived")
					}
				}
				newConn := openEcho(t, e.client(t, "alice", password))
				newConn.Close()
			})
		}
	}
}
