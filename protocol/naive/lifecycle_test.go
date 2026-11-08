package naive_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/naive"
)

func TestNaiveStartFailureReleasesBothListeners(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			options, _ := fixtureOptions(t, &option.WebOptions{Type: "static", Content: "website"})
			var occupied io.Closer
			if network == "tcp" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				occupied = listener
				options.ListenPort = uint16(listener.Addr().(*net.TCPAddr).Port)
			} else {
				listener, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				occupied = listener
				options.ListenPort = uint16(listener.LocalAddr().(*net.UDPAddr).Port)
			}
			t.Cleanup(func() { _ = occupied.Close() })
			created, err := naive.NewInbound(context.Background(), &echoRouter{t: t}, log.NewNOPFactory().Logger(), "conflict", options)
			if err != nil {
				t.Fatal(err)
			}
			n := created.(*naive.Inbound)
			scope := adapter.NewScope(context.Background(), log.NewNOPFactory().Logger())
			t.Cleanup(func() { _ = scope.Close() })
			if err = n.Start(adapter.StartStateStart, scope); err == nil {
				t.Fatal("dual listener startup ignored an occupied port")
			}
			if err = n.Close(); err != nil {
				t.Fatal(err)
			}
			_ = occupied.Close()
			address := fmt.Sprintf("127.0.0.1:%d", options.ListenPort)
			tcp, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatalf("TCP listener leaked after failed start: %v", err)
			}
			defer tcp.Close()
			udp, err := net.ListenPacket("udp", address)
			if err != nil {
				t.Fatalf("UDP listener leaked after failed start: %v", err)
			}
			defer udp.Close()
		})
	}
}

func TestNaiveCloseInterruptsUnfinishedHandshake(t *testing.T) {
	n, address, _, _ := fixture(t)
	client, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Deliberately leave TLS incomplete; shutdown must not wait for its timeout.
	if _, err = client.Write([]byte{0x16, 0x03, 0x01}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- n.Close() }()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close waited for TLS handshake deadline")
	}
}
