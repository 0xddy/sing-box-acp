package option

import (
	"strings"
	"testing"
)

func TestWebOptionsValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options WebOptions
	}{
		{"unknown-mode", WebOptions{Type: "unknown"}},
		{"missing-title", WebOptions{Type: "static"}},
		{"static-url", WebOptions{Type: "static", Title: "Site", URL: "https://example.com"}},
		{"title-byte-limit", WebOptions{Type: "static", Title: strings.Repeat("界", 86)}},
		{"proxy-content", WebOptions{Type: "proxy", URL: "https://example.com", Body: "wrong mode"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.options.Validate(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, address := range []string{"file:///tmp/site", "https:/example.com", "https://user:password@example.com", "https://@example.com", "https://example.com?", "https://example.com#", "https://example.com:", "https://example.com:0", "https://example.com:65536"} {
		t.Run(address, func(t *testing.T) {
			if err := (WebOptions{Type: "proxy", URL: address}).Validate(); err == nil {
				t.Fatal("invalid URL accepted")
			}
		})
	}
	for _, options := range []WebOptions{{Type: "static", Title: strings.Repeat("x", 256)}, {Type: "proxy", URL: "https://[::1]:8443/site%2Fassets"}} {
		if err := options.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
