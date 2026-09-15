package sniff

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestQUICCryptoReassemblyBoundsAndProgress(t *testing.T) {
	tests := []struct {
		name      string
		fragments []qCryptoFragment
		want      string
		invalid   bool
	}{
		{"out of order", []qCryptoFragment{{2, 2, []byte("cd")}, {0, 2, []byte("ab")}}, "abcd", false},
		{"matching retransmit", []qCryptoFragment{{0, 2, []byte("ab")}, {0, 2, []byte("ab")}}, "ab", false},
		{"partial overlap", []qCryptoFragment{{0, 2, []byte("ab")}, {1, 2, []byte("bc")}}, "abc", false},
		{"gap", []qCryptoFragment{{0, 1, []byte("a")}, {2, 1, []byte("c")}}, "a", false},
		{"zero progress", []qCryptoFragment{{0, 0, nil}}, "", true},
		{"conflicting retransmit", []qCryptoFragment{{0, 1, []byte("a")}, {0, 1, []byte("b")}}, "", true},
		{"offset overflow", []qCryptoFragment{{^uint64(0), 1, []byte("a")}}, "", true},
		{"length beyond payload", []qCryptoFragment{{0, 2, []byte("a")}}, "", true},
		{"reassembly limit", []qCryptoFragment{{maxQUICCryptoBytes, 1, []byte("a")}}, "", true},
		{"fragment limit", make([]qCryptoFragment, maxQUICCryptoFragments+1), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := assembleQUICCrypto(context.Background(), tt.fragments)
			if (err != nil) != tt.invalid || string(data) != tt.want {
				t.Fatalf("data=%q err=%v", data, err)
			}
		})
	}
}

func TestQUICCancelledParseClearsFragments(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	metadata := adapter.InboundContext{SniffContext: []qCryptoFragment{{0, 1, []byte("a")}}}
	if err := QUICClientHello(ctx, &metadata, nil); err != context.Canceled || metadata.SniffContext != nil {
		t.Fatalf("err=%v retained=%v", err, metadata.SniffContext)
	}
}

func FuzzQUICClientHelloBounded(f *testing.F) {
	f.Add([]byte{0xc0, 0, 0, 0, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 64*1024 {
			t.Skip()
		}
		var metadata adapter.InboundContext
		_ = QUICClientHello(context.Background(), &metadata, packet)
	})
}
