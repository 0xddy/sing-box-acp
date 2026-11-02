package juicity

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

func TestWireVectors(t *testing.T) {
	// Official Go client/stream_packet_conn.go uses trojanc.Metadata for the
	// stream destination and again, without a network byte, for each datagram.
	for _, tc := range []struct{ addr, encoded string }{
		{"127.0.0.1:53", "017f0000010035"},
		{"[::1]:53", "04000000000000000000000000000000010035"},
		{"example.com:53", "030b6578616d706c652e636f6d0035"},
	} {
		dst := M.ParseSocksaddr(tc.addr)
		var out bytes.Buffer
		if err := writeHeader(&out, networkUDP, dst); err != nil {
			t.Fatal(err)
		}
		if _, err := writePacket(&out, []byte("hi"), dst); err != nil {
			t.Fatal(err)
		}
		expected, _ := hex.DecodeString("03" + tc.encoded + tc.encoded + "00026869")
		if !bytes.Equal(out.Bytes(), expected) {
			t.Fatalf("%s: %x", tc.addr, out.Bytes())
		}
		for cut := 0; cut < len(expected); cut++ {
			stream := bytes.NewReader(expected[:cut])
			_, _, err := readHeader(stream)
			if err == nil {
				_, _, err = readPacket(stream, make([]byte, 8))
			}
			if err == nil {
				t.Fatalf("accepted truncated frame at %d", cut)
			}
		}
		kind, addr, err := readHeader(&out)
		if err != nil || kind != networkUDP || addr != dst {
			t.Fatal(kind, addr, err)
		}
		b := make([]byte, 8)
		n, addr, err := readPacket(&out, b)
		if err != nil || addr != dst || string(b[:n]) != "hi" {
			t.Fatal(addr, err)
		}
	}
	var out bytes.Buffer
	dst := M.ParseSocksaddr("127.0.0.1:1")
	if _, err := writePacket(&out, make([]byte, 1<<16), dst); err == nil {
		t.Fatal("accepted oversized datagram")
	}
	writePacket(&out, []byte("long"), dst)
	writePacket(&out, []byte("z"), dst)
	var b [1]byte
	readPacket(&out, b[:])
	n, _, err := readPacket(&out, b[:])
	if err != nil || n != 1 || b[0] != 'z' {
		t.Fatal("short read desynchronized the stream")
	}
	if _, _, err = readHeader(bytes.NewReader([]byte{4})); err == nil || err == io.EOF {
		t.Fatal("accepted invalid network")
	}
}

func TestUnderlayVector(t *testing.T) {
	var k key
	for i := range k {
		k[i] = byte(i)
	}
	var s salt
	s[31] = 1
	expected, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001c8c261f01e8bd37186e98ffe01fa159eaf504d81f9")
	got, err := sealPacket(k, s, []byte("first"))
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("%x, %v", got, err)
	}
	_, plain, err := openPacket(k, expected)
	if err != nil || string(plain) != "first" {
		t.Fatal(err)
	}
	expected[len(expected)-1] ^= 1
	if _, _, err = openPacket(k, expected); err == nil {
		t.Fatal("accepted tampered ciphertext")
	}
	for i := range expected {
		if _, _, err = openPacket(k, expected[:i]); err == nil {
			t.Fatalf("accepted truncated ciphertext at %d", i)
		}
	}
}
