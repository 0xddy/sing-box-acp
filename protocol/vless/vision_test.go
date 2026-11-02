//go:build with_utls

package vless_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
)

// Buffer writes only when the test needs a TLS record and the following raw
// bytes to arrive in the same underlying read.
type visionWire struct {
	net.Conn
	pending *bytes.Buffer
}

func (w *visionWire) Write(data []byte) (int, error) {
	if w.pending != nil {
		return w.pending.Write(data)
	}
	return w.Conn.Write(data)
}

func visionPair(t *testing.T) (*tls.Conn, *utls.Conn, *visionWire) {
	t.Helper()
	issuer := httptest.NewTLSServer(nil)
	defer issuer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(issuer.Certificate())
	cert := issuer.TLS.Certificates[0]

	left, right := net.Pipe()
	t.Cleanup(func() { left.Close(); right.Close() })
	deadline := time.Now().Add(10 * time.Second)
	left.SetDeadline(deadline)
	right.SetDeadline(deadline)
	wire := &visionWire{Conn: left}
	client := tls.Client(wire, &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS13})
	server := utls.Server(right, &utls.Config{
		Certificates: []utls.Certificate{{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey}},
		MinVersion:   tls.VersionTLS13, SessionTicketsDisabled: true,
	})
	clientReady := make(chan error, 1)
	go func() { clientReady <- client.Handshake() }()
	if err := server.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-clientReady; err != nil {
		t.Fatal(err)
	}
	return client, server, wire
}

func wrapVision(t *testing.T, outer net.Conn, uuid [16]byte) *vless.VisionConn {
	t.Helper()
	conn, err := vless.NewVisionConn(outer, outer, uuid, logger.NOP())
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestVisionConcurrentReadWrite(t *testing.T) {
	client, server, _ := visionPair(t)
	id := [16]byte{1}
	fromClient, fromServer := wrapVision(t, client, id), wrapVision(t, server, id)
	results := make(chan error, 4)
	for _, direction := range []struct {
		src, dst net.Conn
		value    byte
	}{{fromClient, fromServer, 'a'}, {fromServer, fromClient, 'b'}} {
		go func() {
			for range 16 {
				if _, err := direction.src.Write([]byte{direction.value}); err != nil {
					results <- err
					return
				}
			}
			results <- nil
		}()
		go func() {
			payload := make([]byte, 16)
			_, err := io.ReadFull(direction.dst, payload)
			if err == nil && !bytes.Equal(payload, bytes.Repeat([]byte{direction.value}, len(payload))) {
				t.Errorf("received %x in direction %q", payload, direction.value)
			}
			results <- err
		}()
	}
	for range 4 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestVisionTLS13DirectRead(t *testing.T) {
	client, server, wire := visionPair(t)
	id := [16]byte{1}
	vision := wrapVision(t, server, id)
	content := []byte("last authenticated record")
	// UUID, direct command, content length and zero padding.
	frame := append(bytes.Clone(id[:]), 2, 0, byte(len(content)), 0, 0)
	wire.pending = new(bytes.Buffer)
	if _, err := client.Write(append(frame, content...)); err != nil {
		t.Fatal(err)
	}
	// A raw 0x15 can follow the last TLS 1.3 record without being a TLS alert.
	tail := []byte{0x15, 0x44, 0xe8, 0, 2, 0xaa, 0xbb}
	packet := append(wire.pending.Bytes(), tail...)
	sent := make(chan error, 1)
	go func() { _, err := wire.Conn.Write(packet); sent <- err }()
	// Drain any alert sent by a regressed TLS implementation on the pipe.
	go io.Copy(io.Discard, wire.Conn)
	want := append(bytes.Clone(content), tail...)
	got := make([]byte, len(want))
	if _, err := io.ReadFull(vision, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("direct read = %x, want %x", got, want)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}
