package sniff

import "testing"

func TestAnalysisServerNameDoesNotAttributeECHOuterName(t *testing.T) {
	if name := analysisServerName("public.example.com", []uint16{0, 43, 0xfe0d}); name != "" {
		t.Fatal("ECH cover name treated as destination", name)
	}
	if name := analysisServerName("www.example.com", []uint16{0, 43}); name != "www.example.com" {
		t.Fatal(name)
	}
}
