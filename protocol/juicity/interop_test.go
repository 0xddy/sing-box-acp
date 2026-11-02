//go:build with_quic

package juicity_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	J "github.com/sagernet/sing-box/protocol/juicity"
	SJ "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

const testUUID = "12345678-1234-4123-8123-123456789012"
const otherUUID = "12345678-1234-4123-8123-123456789013"
const password = "loopback-only"

const rustReleaseDir = "JUICITY_RUST_DIR"  // juicity-rs v1.1.4
const legacyGoDir = "JUICITY_OFFICIAL_DIR" // juicity v0.5.0

type obj = map[string]any
type fixture struct {
	port           int
	cert, key, pin string
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) int {
	p, err := net.ListenPacket("udp4", "127.0.0.1:0")
	check(t, err)
	defer p.Close()
	return p.LocalAddr().(*net.UDPAddr).Port
}

func newFixture(t *testing.T) fixture {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	crt := srv.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(crt.PrivateKey)
	check(t, err)
	f := fixture{port: freePort(t), cert: filepath.Join(t.TempDir(), "cert.pem"), key: filepath.Join(t.TempDir(), "key.pem")}
	check(t, os.WriteFile(f.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Certificate[0]}), 0600))
	check(t, os.WriteFile(f.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
	sum := sha256.Sum256(crt.Certificate[0])
	f.pin = base64.URLEncoding.EncodeToString(sum[:])
	return f
}

func startBox(t *testing.T, config obj) *box.Box {
	if os.Getenv("JUICITY_TEST_DEBUG") != "" {
		config["log"] = obj{"level": "debug"}
	}
	ctx := include.Context(t.Context())
	v, err := json.Marshal(config)
	check(t, err)
	options, err := SJ.UnmarshalExtendedContext[option.Options](ctx, v)
	check(t, err)
	b, err := box.New(box.Options{Context: ctx, Options: options})
	check(t, err)
	if err = b.Start(); err != nil {
		_ = b.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { check(t, b.Close()) })
	return b
}

func (f fixture) server(t *testing.T) *J.Inbound {
	b := startBox(t, obj{
		"log": obj{"disabled": true},
		"dns": obj{"servers": []obj{{"type": "hosts", "tag": "local", "predefined": obj{"localhost": "127.0.0.1"}}}},
		"route": obj{"default_domain_resolver": "local", "rules": []obj{
			{"auth_user": []string{"first", "second"}, "action": "route", "outbound": "direct"},
			{"inbound": "in", "action": "reject"},
		}},
		"outbounds": []obj{{"type": "direct", "tag": "direct"}},
		"inbounds": []obj{{
			"type": "juicity", "tag": "in", "listen": "127.0.0.1",
			"listen_port": f.port, "max_concurrent_streams": 30,
			"users": []obj{{"name": "first", "uuid": testUUID, "password": password}, {"name": "second", "uuid": otherUUID, "password": password}},
			"tls":   obj{"enabled": true, "certificate_path": f.cert, "key_path": f.key},
		}},
	})
	in, _ := b.Inbound().Get("in")
	return in.(*J.Inbound)
}

func (f fixture) client(t *testing.T, mode, id, pw string) adapter.Outbound {
	out := obj{
		"type": "juicity", "tag": "out", "server": "127.0.0.1", "server_port": f.port,
		"uuid": id, "password": pw,
		"tls": obj{"enabled": true, "server_name": "example.com"},
	}
	if mode != "" {
		out["udp_mode"] = mode
	}
	if f.pin != "" {
		out["pinned_certchain_sha256"] = f.pin
	} else {
		out["tls"].(obj)["certificate_path"] = f.cert
	}
	b := startBox(t, obj{"log": obj{"disabled": true}, "outbounds": []obj{out}})
	v, _ := b.Outbound().Outbound("out")
	return v
}

func target(t *testing.T, network string) int {
	if network == "tcp" {
		l, err := net.Listen("tcp", ":0")
		check(t, err)
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				go func() { defer c.Close(); _, _ = c.Write([]byte("hello")); _, _ = io.Copy(c, c) }()
			}
		}()
		return l.Addr().(*net.TCPAddr).Port
	}
	c, err := net.ListenPacket("udp", ":0")
	check(t, err)
	t.Cleanup(func() { c.Close() })
	go func() {
		p := make([]byte, 65535)
		for {
			n, a, e := c.ReadFrom(p)
			if e != nil {
				return
			}
			_, _ = c.WriteTo(p[:n], a)
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func greeting(t *testing.T, c net.Conn) {
	t.Helper()
	check(t, c.SetDeadline(time.Now().Add(4*time.Second)))
	var b [5]byte
	_, err := io.ReadFull(c, b[:])
	check(t, err)
	if string(b[:]) != "hello" {
		t.Fatalf("greeting %q", b)
	}
}

func exchange(t *testing.T, c net.PacketConn, dst M.Socksaddr, msg string) []byte {
	t.Helper()
	check(t, c.SetDeadline(time.Now().Add(4*time.Second)))
	var addr net.Addr = dst
	if _, native := c.(*net.UDPConn); native {
		addr = dst.UDPAddr()
	}
	_, e := c.WriteTo([]byte(msg), addr)
	check(t, e)
	b := make([]byte, 2048)
	n, _, e := c.ReadFrom(b)
	check(t, e)
	return b[:n]
}

func assertUDP(t *testing.T, c net.PacketConn, dst M.Socksaddr, msg string) {
	t.Helper()
	if got := exchange(t, c, dst, msg); string(got) != msg {
		t.Fatalf("UDP %s: got %x want %x", dst, got, msg)
	}
}

func checkOutbound(t *testing.T, out adapter.Outbound) {
	tcp, udp, other := target(t, "tcp"), target(t, "udp"), target(t, "udp")
	packet, err := out.ListenPacket(t.Context(), M.Socksaddr{})
	check(t, err)
	defer packet.Close()
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		dst := M.ParseSocksaddrHostPort(host, uint16(tcp))
		c, err := out.DialContext(t.Context(), "tcp", dst)
		check(t, err)
		greeting(t, c)
		_, err = c.Write([]byte("data"))
		check(t, err)
		var b [4]byte
		_, err = io.ReadFull(c, b[:])
		check(t, err)
		if string(b[:]) != "data" {
			t.Fatal("TCP mismatch")
		}
		c.Close()
		for _, port := range []int{udp, other, udp} {
			assertUDP(t, packet, M.ParseSocksaddrHostPort(host, uint16(port)), fmt.Sprintf("udp-%s-%d", host, port))
		}
	}
}

func TestJuicityTransports(t *testing.T) {
	f := newFixture(t)
	f.server(t)
	for _, mode := range []string{"auto", "stream", "underlay"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			checkOutbound(t, f.client(t, mode, testUUID, password))
		})
	}
}

func TestJuicityAuthentication(t *testing.T) {
	f := newFixture(t)
	in := f.server(t)
	dst := M.ParseSocksaddrHostPort("127.0.0.1", uint16(target(t, "tcp")))
	out := f.client(t, "auto", testUUID, password)
	// Continue holding the first 30 streams while opening the next connection.
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < 31; i++ {
		c, e := out.DialContext(t.Context(), "tcp", dst)
		check(t, e)
		greeting(t, c)
		held = append(held, c)
	}
	_, e := held[0].Write([]byte("still open"))
	check(t, e)
	proof := make([]byte, len("still open"))
	_, e = io.ReadFull(held[0], proof)
	check(t, e)
	if string(proof) != "still open" {
		t.Fatal("stream rotation interrupted existing connection")
	}
	other := f.client(t, "auto", otherUUID, password)
	survivor, e := other.DialContext(t.Context(), "tcp", dst)
	check(t, e)
	defer survivor.Close()
	greeting(t, survivor)
	if e = in.UpdateUsers([]option.JuicityUser{{UUID: "invalid", Password: "p"}}); e == nil {
		t.Fatal("invalid update accepted")
	}
	good := []option.JuicityUser{{Name: "first", UUID: testUUID, Password: password}, {Name: "second", UUID: otherUUID, Password: password}}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.Context().Done():
				return
			case <-ticker.C:
				_ = in.UpdateUsers(good)
			}
		}
	}()
	for i := 0; i < 5; i++ {
		fresh := f.client(t, "auto", testUUID, password)
		c, e := fresh.DialContext(t.Context(), "tcp", dst)
		check(t, e)
		greeting(t, c)
		c.Close()
	}
	close(stop)
	<-done
	good[0].Password = "rotated"
	check(t, in.UpdateUsers(good))
	for _, c := range held {
		_, e = c.Read(make([]byte, 1))
		if e == nil {
			t.Fatal("revoked connection survived")
		}
	}
	_, e = survivor.Write([]byte("ok"))
	check(t, e)
	b := make([]byte, 2)
	_, e = io.ReadFull(survivor, b)
	check(t, e)
	if string(b) != "ok" {
		t.Fatal("other user's stream changed")
	}
	if n := in.CloseUserSessions("second"); n != 1 {
		t.Fatalf("kicked %d sessions", n)
	}
	for _, bad := range []struct {
		f  fixture
		pw string
	}{{f, password}, {func() fixture { bad := f; bad.pin = base64.StdEncoding.EncodeToString(make([]byte, 32)); return bad }(), "rotated"}} {
		c, e := bad.f.client(t, "stream", testUUID, bad.pw).DialContext(t.Context(), "tcp", dst)
		if e == nil {
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			_, e = c.Read(make([]byte, 1))
		}
		if e == nil {
			t.Fatal("invalid credentials or pin accepted")
		}
	}
	f.pin = ""
	c, e := f.client(t, "stream", testUUID, "rotated").DialContext(t.Context(), "tcp", dst)
	check(t, e)
	defer c.Close()
	greeting(t, c)
}

func upstream(t *testing.T, dirEnv, name string, config obj) {
	t.Helper()
	dir := os.Getenv(dirEnv)
	if dir == "" {
		t.Skipf("set %s to the upstream binary directory", dirEnv)
	}
	executable := filepath.Join(dir, name)
	if dirEnv == rustReleaseDir {
		version, err := exec.Command(executable, "--version").CombinedOutput()
		check(t, err)
		if !strings.HasPrefix(strings.TrimSpace(string(version)), "v1.1.4\n") {
			t.Fatalf("expected juicity-rs v1.1.4, got %q", version)
		}
	}
	config["log_level"] = "debug"
	data, err := json.Marshal(config)
	check(t, err)
	path := filepath.Join(t.TempDir(), "config.json")
	check(t, os.WriteFile(path, data, 0600))
	cmd := exec.Command(executable, "run", "-c", path)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	check(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(output.String())
		}
	})
	if name == "juicity-server" {
		// The UDP listener must exist before the first QUIC Initial is sent.
		var port int
		_, err := fmt.Sscanf(config["listen"].(string), "127.0.0.1:%d", &port)
		check(t, err)
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			probe, e := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
			if e != nil {
				return
			}
			_ = probe.Close()
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("official server did not bind its UDP port")
	}
}

func startUpstreamServer(t *testing.T, dirEnv string) fixture {
	t.Helper()
	f := newFixture(t)
	upstream(t, dirEnv, "juicity-server", obj{
		"listen": fmt.Sprintf("127.0.0.1:%d", f.port), "users": obj{testUUID: password},
		"certificate": f.cert, "private_key": f.key, "congestion_control": "bbr",
	})
	return f
}

func TestJuicityRustServer(t *testing.T) {
	f := startUpstreamServer(t, rustReleaseDir)
	out := f.client(t, "auto", testUUID, password)
	checkOutbound(t, out)
	portZeroHint := M.ParseSocksaddr("127.0.0.1:0")
	dst := M.ParseSocksaddrHostPort("127.0.0.1", uint16(target(t, "udp")))
	for _, tc := range []struct{ name, mode string }{{"omitted", ""}, {"auto", "auto"}} {
		t.Run("port-zero-"+tc.name, func(t *testing.T) {
			peer := f.client(t, tc.mode, testUUID, password)
			p, err := peer.ListenPacket(t.Context(), portZeroHint)
			check(t, err)
			defer p.Close()
			assertUDP(t, p, dst, "first")
			assertUDP(t, p, dst, "second")
		})
	}
}

// A compatibility observation specific to v1.1.4. ACP uses the per-datagram
// key schedule from juicity_common::crypto::juicity_underlay.
func TestJuicityRustUnderlayV114Limit(t *testing.T) {
	f := startUpstreamServer(t, rustReleaseDir)
	target, err := net.ListenPacket("udp4", "127.0.0.1:0")
	check(t, err)
	defer target.Close()
	dst := M.SocksaddrFromNet(target.LocalAddr())
	out := f.client(t, "underlay", testUUID, password)
	p, err := out.ListenPacket(t.Context(), dst)
	check(t, err)
	defer p.Close()

	_, err = p.WriteTo([]byte("first"), dst)
	check(t, err)
	check(t, target.SetReadDeadline(time.Now().Add(4*time.Second)))
	var buf [256]byte
	n, source, err := target.ReadFrom(buf[:])
	check(t, err)
	if string(buf[:n]) != "first" {
		t.Fatalf("first Underlay datagram at target: %x", buf[:n])
	}
	// Exercise each direction separately. Success on the first request alone
	// cannot detect the server caching the first subkey for the whole session.
	_, err = target.WriteTo([]byte("reply"), source)
	check(t, err)
	expectTimeout := func(conn net.PacketConn, direction string) {
		t.Helper()
		check(t, conn.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
		n, _, err := conn.ReadFrom(buf[:])
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("%s: expected v1.1.4 key mismatch, read %d bytes, err=%v", direction, n, err)
		}
	}
	expectTimeout(p, "reply to first request")
	_, err = p.WriteTo([]byte("second"), dst)
	check(t, err)
	expectTimeout(target, "second request")
}

func TestJuicityLegacyGoServer(t *testing.T) {
	f := startUpstreamServer(t, legacyGoDir)
	checkOutbound(t, f.client(t, "stream", testUUID, password))
	t.Run("underlay-first-packet", func(t *testing.T) {
		targetSocket, e := net.ListenPacket("udp4", "127.0.0.1:0")
		check(t, e)
		defer targetSocket.Close()
		dst := M.SocksaddrFromNet(targetSocket.LocalAddr())
		out := f.client(t, "underlay", testUUID, password)
		p, e := out.ListenPacket(t.Context(), dst)
		check(t, e)
		defer p.Close()
		_, e = p.WriteTo([]byte("first"), dst)
		check(t, e)
		check(t, targetSocket.SetDeadline(time.Now().Add(5*time.Second)))
		wire := make([]byte, 2048)
		n, src, e := targetSocket.ReadFrom(wire)
		check(t, e)
		got := wire[:n]
		t.Logf("v0.5.0 UDP target: got %d bytes, want 5; payload %x", len(got), got)
		if len(got) != 32+5+16 {
			t.Errorf("unexpected v0.5.0 first datagram length %d", len(got))
		}
		_, e = p.WriteTo([]byte("second"), dst)
		check(t, e)
		n, src, e = targetSocket.ReadFrom(wire)
		check(t, e)
		if string(wire[:n]) != "second" {
			t.Fatalf("second datagram %x", wire[:n])
		}
		_, e = targetSocket.WriteTo(wire[:n], src)
		check(t, e)
		check(t, p.SetReadDeadline(time.Now().Add(4*time.Second)))
		n, _, e = p.ReadFrom(wire)
		check(t, e)
		if string(wire[:n]) != "second" {
			t.Fatalf("Underlay response %x", wire[:n])
		}
	})
}

func TestJuicityRustClient(t *testing.T)     { testUpstreamClient(t, rustReleaseDir) }
func TestJuicityLegacyGoClient(t *testing.T) { testUpstreamClient(t, legacyGoDir) }

func testUpstreamClient(t *testing.T, dirEnv string) {
	if os.Getenv(dirEnv) == "" {
		t.Skipf("set %s to the upstream binary directory", dirEnv)
	}
	f := newFixture(t)
	f.server(t)
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		t.Run(host, func(t *testing.T) {
			tcp, udp := target(t, "tcp"), target(t, "udp")
			local := fmt.Sprintf("127.0.0.1:%d", freePort(t))
			upstream(t, dirEnv, "juicity-client", obj{
				"server": fmt.Sprintf("127.0.0.1:%d", f.port), "uuid": testUUID, "password": password,
				"sni": "example.com", "congestion_control": "bbr", "pinned_certchain_sha256": f.pin,
				"forward": obj{local + "/tcp": net.JoinHostPort(host, fmt.Sprint(tcp)), local + "/udp": net.JoinHostPort(host, fmt.Sprint(udp))},
			})
			var c net.Conn
			var err error
			deadline := time.Now().Add(4 * time.Second)
			for time.Now().Before(deadline) {
				c, err = net.DialTimeout("tcp", local, 100*time.Millisecond)
				if err == nil {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			check(t, err)
			defer c.Close()
			greeting(t, c)
			_, err = c.Write([]byte("ping"))
			check(t, err)
			b := make([]byte, 4)
			_, err = io.ReadFull(c, b)
			check(t, err)
			if string(b) != "ping" {
				t.Fatal("TCP mismatch")
			}
			p, err := net.ListenPacket("udp4", "127.0.0.1:0")
			check(t, err)
			defer p.Close()
			for _, msg := range []string{"first", "second"} {
				assertUDP(t, p, M.ParseSocksaddr(local), msg)
			}
		})
	}
}
