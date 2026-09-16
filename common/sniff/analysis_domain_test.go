package sniff

import (
	"bytes"
	"context"
	"encoding/binary"
	"slices"
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing-box/adapter"
)

func TestTLSClientHelloPreservesVisibleNameAndECHPresence(t *testing.T) {
	for _, ech := range []bool{true, false} {
		name := "plain"
		if ech {
			name = "grease_ech"
		}
		t.Run(name, func(t *testing.T) {
			client := utls.UClient(nil, &utls.Config{ServerName: "www.google.com"}, utls.HelloChrome_133)
			if err := client.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			isECH := func(extension utls.TLSExtension) bool {
				_, ok := extension.(*utls.GREASEEncryptedClientHelloExtension)
				return ok
			}
			if !slices.ContainsFunc(client.Extensions, isECH) {
				t.Fatal("Chrome fixture did not generate GREASE ECH")
			}
			if !ech {
				client.Extensions = slices.DeleteFunc(client.Extensions, isECH)
				if err := client.MarshalClientHello(); err != nil {
					t.Fatal(err)
				}
			}
			hello := client.HandshakeState.Hello.Raw
			record := make([]byte, 5, 5+len(hello))
			record[0], record[1], record[2] = 0x16, 0x03, 0x03
			binary.BigEndian.PutUint16(record[3:], uint16(len(hello)))
			record = append(record, hello...)
			metadata := adapter.InboundContext{SniffECHPresent: true}
			if err := TLSClientHello(context.Background(), &metadata, bytes.NewReader(record)); err != nil {
				t.Fatal(err)
			}
			if metadata.Protocol != "tls" || metadata.Domain != "www.google.com" || metadata.SniffDomain != metadata.Domain || metadata.SniffECHPresent != ech {
				t.Fatalf("ClientHello observations changed: %+v", metadata)
			}
		})
	}
}
