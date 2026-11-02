package mieru_test

import (
	"context"
	"fmt"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/mieru"
	SJ "github.com/sagernet/sing/common/json"
)

func configured(ctx context.Context, raw string) (*box.Box, error) {
	opts, err := SJ.UnmarshalExtendedContext[option.Options](ctx, []byte(raw))
	if err != nil {
		return nil, err
	}
	return box.New(box.Options{Context: ctx, Options: opts})
}

func TestEmptyInboundLifecycle(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		t.Run(transport, func(t *testing.T) {
			ctx := include.Context(t.Context())
			sock, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := sock.Addr().(*net.TCPAddr).Port
			sock.Close()
			raw := fmt.Sprintf(`{"inbounds":[{"type":"mieru","tag":"m","listen":"127.0.0.1","listen_port":%d,"transport":%q}]}`, port, transport)
			for i := 0; i < 3; i++ {
				b, err := configured(ctx, raw)
				if err != nil {
					t.Fatal(err)
				}
				if err = b.Start(); err != nil {
					b.Close()
					t.Fatal(err)
				}
				other, err := configured(include.Context(t.Context()), raw)
				if err != nil {
					t.Fatal(err)
				}
				if err = other.Start(); err == nil {
					other.Close()
					b.Close()
					t.Fatal("empty inbound did not reserve the port")
				}
				other.Close()
				in, _ := b.Inbound().Get("m")
				impl := in.(*mieru.Inbound)
				users := []option.MieruUser{{Name: "alice", Password: "ok"}}
				if err := impl.UpdateUsers(users); err != nil {
					t.Fatal(err)
				}
				if err := impl.UpdateUsers(append(users, users[0])); err == nil {
					t.Fatal("duplicate accepted")
				}
				if err := impl.UpdateUsers(nil); err != nil {
					t.Fatal(err)
				}
				if n := impl.CloseUserSessions("alice"); n != 0 {
					t.Fatalf("closed %d nonexistent sessions", n)
				}
				if err := b.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestInvalidUpdatePreservesLiveCredential(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	raw := fmt.Sprintf(`{"inbounds":[{"type":"mieru","tag":"m","listen":"127.0.0.1","listen_port":%[1]d}],"outbounds":[{"type":"direct","tag":"direct"},{"type":"mieru","tag":"client","server":"127.0.0.1","server_port":%[1]d,"username":"alice","password":"correct"}],"route":{"rules":[{"auth_user":"alice","outbound":"direct"},{"action":"reject"}]}}`, port)
	b, err := configured(include.Context(t.Context()), raw)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err = b.Start(); err != nil {
		t.Fatal(err)
	}
	inbound, _ := b.Inbound().Get("m")
	live := inbound.(*mieru.Inbound)
	table := []option.MieruUser{{Name: "alice", Password: "correct"}}
	if err := live.UpdateUsers(table); err != nil {
		t.Fatal(err)
	}
	if err := live.UpdateUsers([]option.MieruUser{{Name: "alice", Password: "different"}, {Name: "bob"}}); err == nil {
		t.Fatal("accepted incomplete credentials")
	}
	client, _ := b.Outbound().Outbound("client")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", M.SocksaddrFromNet(target.Addr()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err = io.ReadFull(conn, data[:]); err != nil || data[0] != 'x' {
		t.Fatalf("live credential lost: %q, %v", data, err)
	}
	if err := live.UpdateUsers(nil); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Read(data[:]); err == nil {
		t.Fatal("clearing all users left session open")
	}
}

func TestConfigValidation(t *testing.T) {
	for _, fields := range []string{`"transport":"quic"`, `"traffic_pattern":"%%"`, `"mtu":1600`, `"multiplexing":"unknown"`, `"handshake_mode":"unknown"`, `"server_ports":["10:12"]`} {
		raw := `{"outbounds":[{"type":"mieru","server":"127.0.0.1","server_port":10,"username":"alice","password":"ok",` + fields + `}]}`
		if b, err := configured(include.Context(t.Context()), raw); err == nil {
			b.Close()
			t.Fatalf("accepted invalid config %s", fields)
		}
	}
}
