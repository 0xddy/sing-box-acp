//go:build with_quic

package juicity_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
)

// Generated and decrypted with juicity-rs v1.1.4's juicity_underlay helpers.
// The Go v0.5.0 codec at daeuniverse/outbound c607702d1c85 emits the same bytes.
// key = 00..1f; salt = 31 zero bytes followed by 01, 02 or 03.
var underlayFixtures = []string{
	"0000000000000000000000000000000000000000000000000000000000000001c8c261f01e8bd37186e98ffe01fa159eaf504d81f9",
	"0000000000000000000000000000000000000000000000000000000000000002b8e9f5ccbc3a73d4e828e76b12a1fe96af20846f80f1",
	"0000000000000000000000000000000000000000000000000000000000000003ddacfe84cc0a7490bdfdfa597ccbc69b0ec0e5b628",
}

// The optional executable calls the actual Rust library. Keep the published
// vectors available when running the Go tests without a Rust toolchain.
func rustUnderlayCodec(t *testing.T, executable, operation string, data ...[]byte) []byte {
	t.Helper()
	const key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	args := []string{operation, key}
	for _, b := range data {
		args = append(args, hex.EncodeToString(b))
	}
	out, err := exec.Command(executable, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("Rust Underlay %s: %v: %s", operation, err, out)
	}
	result, err := hex.DecodeString(string(bytes.TrimSpace(out)))
	check(t, err)
	return result
}

func TestJuicityUnderlayWire(t *testing.T) {
	codec := os.Getenv("JUICITY_RUST_CODEC")
	payloads := [...]string{"first", "second", "third"}
	for _, revoke := range []string{"remove", "password", "kick"} {
		t.Run(revoke, func(t *testing.T) {
			f := newFixture(t)
			server := f.server(t)
			cert, e := os.ReadFile(f.cert)
			check(t, e)
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(cert)
			remote := net.JoinHostPort("127.0.0.1", strconv.Itoa(f.port))
			qc, e := quic.DialAddr(t.Context(), remote, &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}, nil)
			check(t, e)
			defer qc.CloseWithError(0, "")
			stream, e := qc.OpenUniStreamSync(t.Context())
			check(t, e)
			id, _ := hex.DecodeString("12345678123441238123123456789012")
			state := qc.ConnectionState().TLS
			token, e := state.ExportKeyingMaterial(string(id), []byte(password), 32)
			check(t, e)
			_, e = stream.Write(append(append([]byte{0, 0}, id...), token...))
			check(t, e)
			data, e := net.Dial("udp4", remote)
			check(t, e)
			defer data.Close()
			target, e := net.ListenPacket("udp4", "127.0.0.1:0")
			check(t, e)
			defer target.Close()
			wire := make([][]byte, len(underlayFixtures))
			for i, s := range underlayFixtures {
				wire[i], e = hex.DecodeString(s)
				check(t, e)
				if codec != "" {
					packet := rustUnderlayCodec(t, codec, "seal", wire[i][:32], []byte(payloads[i]))
					if !bytes.Equal(packet, wire[i]) {
						t.Fatalf("Rust Underlay wire vector %d changed", i)
					}
					wire[i] = packet
				}
			}
			_, e = data.Write(wire[0])
			check(t, e)
			// The registration may arrive later than the first encrypted UDP packet.
			var reg bytes.Buffer
			reg.Write(wire[0][:32])
			for i := 0; i < 32; i++ {
				reg.WriteByte(byte(i))
			}
			reg.Write([]byte{1, 127, 0, 0, 1})
			reg.Write(binary.BigEndian.AppendUint16(nil, uint16(target.LocalAddr().(*net.UDPAddr).Port)))
			_, e = stream.Write(reg.Bytes())
			check(t, e)
			readTarget := func(want string) net.Addr {
				t.Helper()
				b := make([]byte, 64)
				target.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, source, e := target.ReadFrom(b)
				check(t, e)
				if string(b[:n]) != want {
					t.Fatalf("got %x want %q", b[:n], want)
				}
				return source
			}
			readTarget("first")
			_, e = data.Write(wire[0])
			check(t, e)
			forged := bytes.Clone(wire[1])
			forged[len(forged)-1] ^= 0xff
			_, e = data.Write(forged)
			check(t, e)
			_, e = data.Write(wire[1])
			check(t, e)
			source := readTarget("second")
			_, e = target.WriteTo([]byte("reply"), source)
			check(t, e)
			check(t, data.SetReadDeadline(time.Now().Add(2*time.Second)))
			reflection := make([]byte, 96)
			n, e := data.Read(reflection)
			check(t, e)
			if codec != "" {
				if plain := rustUnderlayCodec(t, codec, "open", reflection[:n]); string(plain) != "reply" {
					t.Fatalf("Rust Underlay decrypted reply %x", plain)
				}
			}
			_, e = data.Write(reflection[:n])
			check(t, e)
			target.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, _, e = target.ReadFrom(make([]byte, 64)); !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatalf("reflected reply was forwarded: %v", e)
			}
			switch revoke {
			case "kick":
				if server.CloseUserSessions("first") != 1 {
					t.Fatal("session not kicked")
				}
			case "remove":
				check(t, server.UpdateUsers(nil))
			case "password":
				check(t, server.UpdateUsers([]option.JuicityUser{{Name: "first", UUID: testUUID, Password: "new"}}))
			}
			_, e = data.Write(wire[2])
			check(t, e)
			target.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			_, _, e = target.ReadFrom(make([]byte, 64))
			if !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatalf("revoked data reached target: %v", e)
			}
		})
	}
}
