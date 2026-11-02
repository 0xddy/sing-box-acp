//go:build with_quic

package juicity_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
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
