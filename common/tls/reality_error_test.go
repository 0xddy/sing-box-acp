package tls

import (
	"errors"
	"fmt"
	"testing"
)

func TestNormalizeRealityServerError(t *testing.T) {
	source := errors.New(realityInvalidConnectionMessage)
	normalized := normalizeRealityServerError(source)
	if !IsRealityInvalidConnection(normalized) {
		t.Fatal("normalized REALITY probe error was not classified")
	}
	if normalized.Error() != source.Error() {
		t.Fatalf("normalized error = %q, want %q", normalized, source)
	}
	if !errors.Is(normalized, source) {
		t.Fatal("normalized error lost its original cause")
	}
	if !IsRealityInvalidConnection(fmt.Errorf("TLS handshake: %w", normalized)) {
		t.Fatal("wrapped REALITY probe error was not classified")
	}
}

func TestNormalizeRealityServerErrorKeepsOtherFailures(t *testing.T) {
	tests := []error{
		nil,
		errors.New("REALITY: processed invalid connection from another implementation"),
		errors.New("dial handshake server: i/o timeout"),
	}
	for _, input := range tests {
		normalized := normalizeRealityServerError(input)
		if normalized != input {
			t.Fatalf("normalizeRealityServerError(%v) changed an unrelated error", input)
		}
		if IsRealityInvalidConnection(normalized) {
			t.Fatalf("normalizeRealityServerError(%v) classified an unrelated error", input)
		}
	}
}
