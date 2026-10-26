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
		{"missing-content", WebOptions{Type: "static"}},
		{"blank-content", WebOptions{Type: "static", Content: " \n\t "}},
		{"static-url", WebOptions{Type: "static", Content: "<h1>Site</h1>", URL: "https://example.com"}},
		{"content-byte-limit", WebOptions{Type: "static", Content: strings.Repeat("界", 21846)}},
		{"proxy-content", WebOptions{Type: "proxy", URL: "https://example.com", Content: "wrong mode"}},
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
	for _, options := range []WebOptions{{Type: "static", Content: strings.Repeat("x", 65536)}, {Type: "proxy", URL: "https://[::1]:8443/site%2Fassets"}} {
		if err := options.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}
