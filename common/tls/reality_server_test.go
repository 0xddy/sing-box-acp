//go:build with_utls

package tls

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestRealityServerRejectsMalformedShortID(t *testing.T) {
	for _, shortID := range []string{"0123456789abcdef00", "0123456789abcdef0", "secret-not-hex", "abc"} {
		t.Run(shortID, func(t *testing.T) {
			_, err := NewRealityServer(context.Background(), nil, option.InboundTLSOptions{
				ServerName: "www.example.com",
				Reality: &option.InboundRealityOptions{
					Enabled:    true,
					PrivateKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					ShortID:    []string{shortID},
				},
			})
			if err == nil || !strings.Contains(err.Error(), "short_id[0]") {
				t.Fatalf("expected short ID validation error, got %v", err)
			}
			if strings.Contains(err.Error(), shortID) {
				t.Fatalf("validation error leaked short ID: %v", err)
			}
		})
	}
}
