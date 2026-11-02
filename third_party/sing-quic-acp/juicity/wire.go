package juicity

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"

	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	networkTCP = 1
	networkUDP = 3
	authSize   = 50
	maxPayload = 65535
)

type User struct {
	Name     string
	UUID     [16]byte
	Password string
}

func authFrame(state tls.ConnectionState, user User) ([authSize]byte, error) {
	var frame [authSize]byte
	token, err := state.ExportKeyingMaterial(string(user.UUID[:]), []byte(user.Password), 32)
	if err != nil {
		return frame, err
	}
	copy(frame[2:18], user.UUID[:])
	copy(frame[18:], token)
	return frame, nil
}

func verifyAuth(state tls.ConnectionState, frame [authSize]byte, table map[[16]byte]User) (User, error) {
	var id [16]byte
	copy(id[:], frame[2:18])
	user, ok := table[id]
	if !ok || frame[0] != 0 || frame[1] != 0 {
		return User{}, errors.New("invalid Juicity authentication")
	}
	expected, err := authFrame(state, user)
	if err != nil || !hmac.Equal(expected[:], frame[:]) {
		return User{}, errors.New("invalid Juicity authentication")
	}
	return user, nil
}

func writeHeader(w io.Writer, network byte, dst M.Socksaddr) error {
	var b bytes.Buffer
	b.WriteByte(network)
	if err := M.SocksaddrSerializer.WriteAddrPort(&b, dst); err != nil {
		return err
	}
	_, err := w.Write(b.Bytes())
	return err
}

func readHeader(r io.Reader) (byte, M.Socksaddr, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return 0, M.Socksaddr{}, err
	}
	if kind[0] != networkTCP && kind[0] != networkUDP {
		return 0, M.Socksaddr{}, errors.New("unknown Juicity network")
	}
	dst, err := readDestination(r)
	return kind[0], dst.Unwrap(), err
}

func readDestination(r io.Reader) (M.Socksaddr, error) {
	dst, err := M.SocksaddrSerializer.ReadAddrPort(r)
	if err == nil && !dst.IsValid() {
		err = errors.New("invalid Juicity destination")
	}
	return dst, err
}

func writePacket(w io.Writer, p []byte, dst M.Socksaddr) (int, error) {
	if len(p) > maxPayload {
		return 0, errors.New("Juicity UDP payload too large")
	}
	var b bytes.Buffer
	b.Grow(M.MaxSocksaddrLength + 2 + len(p))
	if err := M.SocksaddrSerializer.WriteAddrPort(&b, dst); err != nil {
		return 0, err
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(p)))
	b.Write(size[:])
	b.Write(p)
	if _, err := w.Write(b.Bytes()); err != nil {
		return 0, err
	}
	return len(p), nil
}

func readPacket(r io.Reader, p []byte) (int, M.Socksaddr, error) {
	dst, err := readDestination(r)
	if err != nil {
		return 0, M.Socksaddr{}, err
	}
	var size [2]byte
	if _, err = io.ReadFull(r, size[:]); err != nil {
		return 0, dst, err
	}
	length := int(binary.BigEndian.Uint16(size[:]))
	n, err := io.ReadFull(r, p[:min(length, len(p))])
	if err == nil && length > n {
		_, err = io.CopyN(io.Discard, r, int64(length-n))
	}
	return n, dst.Unwrap(), err
}

// The first two salt bytes stay clear so quic-go dispatches the packet as non-QUIC.
type salt [32]byte
type key [32]byte
type registration struct {
	Salt        salt
	Key         key
	Destination M.Socksaddr
}

func newSalt() (salt, error) { var s salt; _, err := rand.Read(s[2:]); return s, err }

func newRegistration(dst M.Socksaddr) (registration, error) {
	s, err := newSalt()
	r := registration{Salt: s, Destination: dst}
	if err == nil {
		_, err = rand.Read(r.Key[:])
	}
	return r, err
}

func (r registration) write(w io.Writer) error {
	var b bytes.Buffer
	b.Write(r.Salt[:])
	b.Write(r.Key[:])
	if err := M.SocksaddrSerializer.WriteAddrPort(&b, r.Destination); err != nil {
		return err
	}
	_, err := w.Write(b.Bytes())
	return err
}

func readRegistration(rd io.Reader) (registration, error) {
	var r registration
	if _, err := io.ReadFull(rd, r.Salt[:]); err != nil {
		return r, err
	}
	if r.Salt[0] != 0 || r.Salt[1] != 0 {
		return r, errors.New("invalid Underlay salt")
	}
	if _, err := io.ReadFull(rd, r.Key[:]); err != nil {
		return r, err
	}
	var err error
	r.Destination, err = readDestination(rd)
	return r, err
}

func packetCipher(k key, s salt) (cipher.AEAD, error) {
	var sub key
	_, err := io.ReadFull(hkdf.New(sha1.New, k[:], s[:], []byte("juicity-reused-info")), sub[:])
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(sub[:])
}

func sealPacket(k key, s salt, body []byte) ([]byte, error) {
	aead, err := packetCipher(k, s)
	if err != nil {
		return nil, err
	}
	var nonce [chacha20poly1305.NonceSize]byte
	wire := make([]byte, len(s), len(s)+len(body)+aead.Overhead())
	copy(wire, s[:])
	return aead.Seal(wire, nonce[:], body, nil), nil
}

func openPacket(k key, p []byte) (salt, []byte, error) {
	var s salt
	if len(p) < len(s)+chacha20poly1305.Overhead || p[0] != 0 || p[1] != 0 {
		return s, nil, errors.New("invalid Underlay packet")
	}
	copy(s[:], p)
	aead, err := packetCipher(k, s)
	if err != nil {
		return s, nil, err
	}
	var nonce [chacha20poly1305.NonceSize]byte
	plain, err := aead.Open(nil, nonce[:], p[len(s):], nil)
	return s, plain, err
}
