package sniff

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestPayloadDomainIsSeparateFromReverseDNSHint(t *testing.T) {
	metadata := adapter.InboundContext{Domain: "reverse.example.com"}
	if err := SSH(context.Background(), &metadata, strings.NewReader("SSH-2.0-test-client\r\n")); err != nil {
		t.Fatal(err)
	}
	if metadata.Domain != "reverse.example.com" || metadata.SniffDomain != "" {
		t.Fatal("protocol-only sniff claimed reverse DNS hint", metadata.Domain, metadata.SniffDomain)
	}
	if err := HTTPHost(context.Background(), &metadata, strings.NewReader("GET / HTTP/1.1\r\nHost: visited.example.net\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if metadata.Domain != "visited.example.net" || metadata.SniffDomain != metadata.Domain {
		t.Fatal("HTTP Host not marked as payload-derived", metadata.Domain, metadata.SniffDomain)
	}
}
