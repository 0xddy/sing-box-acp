//go:build with_quic

package juicity_test

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/protocol/juicity"
	M "github.com/sagernet/sing/common/metadata"
)

func TestJuicityRestartAndReconnect(t *testing.T) {
	f := newFixture(t)
	// Reuse the same listening port across starts so a leaked socket fails the next start.
	for i := 0; i < 3; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f.server(t)
			out := f.client(t, "underlay", testUUID, password)
			dst := M.ParseSocksaddrHostPort("127.0.0.1", uint16(target(t, "udp")))
			p, err := out.ListenPacket(t.Context(), dst)
			check(t, err)
			assertUDP(t, p, dst, "before-reset")
			check(t, p.SetDeadline(time.Time{}))
			result := make(chan error, 1)
			go func() { _, _, e := p.ReadFrom(make([]byte, 8)); result <- e }()
			out.(adapter.InterfaceUpdateListener).InterfaceUpdated(t.Context())
			select {
			case e := <-result:
				if e == nil {
					t.Fatal("blocked read survived network change")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("network change did not unblock UDP read")
			}
			_ = p.Close()
			replacement, err := out.ListenPacket(t.Context(), dst)
			check(t, err)
			defer replacement.Close()
			assertUDP(t, replacement, dst, "after-reset")
		})
	}
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", f.port))
	check(t, err)
	conn.Close()
}

func TestJuicityInlineCertificateRotation(t *testing.T) {
	f := newFixture(t)
	cert, err := os.ReadFile(f.cert)
	check(t, err)
	key, err := os.ReadFile(f.key)
	check(t, err)
	server := startBox(t, obj{"inbounds": []obj{{
		"type": "juicity", "tag": "in", "listen": "127.0.0.1", "listen_port": f.port,
		"users": []obj{{"uuid": testUUID, "password": password}},
		"tls":   obj{"enabled": true, "certificate": string(cert), "key": string(key)},
	}}, "outbounds": []obj{{"type": "direct", "tag": "direct"}}})
	in, _ := server.Inbound().Get("in")
	dst := M.ParseSocksaddrHostPort("127.0.0.1", uint16(target(t, "tcp")))
	dial := func(f fixture) net.Conn {
		t.Helper()
		c, err := f.client(t, "auto", testUUID, password).DialContext(t.Context(), "tcp", dst)
		check(t, err)
		greeting(t, c)
		t.Cleanup(func() { c.Close() })
		return c
	}
	active := dial(f)
	replacement, err := tls.GenerateKeyPair(nil, nil, nil, "example.com")
	check(t, err)
	check(t, in.(*juicity.Inbound).UpdateTLSCertificate(replacement))
	sum := sha256.Sum256(replacement.Certificate[0])
	f.pin = base64.URLEncoding.EncodeToString(sum[:])
	dial(f)
	_, err = active.Write([]byte("old"))
	check(t, err)
	var b [3]byte
	_, err = io.ReadFull(active, b[:])
	check(t, err)
	if string(b[:]) != "old" {
		t.Fatal("session interrupted by rotation")
	}
}
