package tls

import (
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestInlineCertificateUpdateIsVisibleThroughClones(t *testing.T) {
	first, err := GenerateKeyPair(nil, nil, time.Now, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(first.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSTDServer(context.Background(), log.NewNOPFactory().Logger(), option.InboundTLSOptions{
		Enabled: true, Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first.Certificate[0]}))},
		Key: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))}, ALPN: []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	clone := server.Clone()
	initialConfig, _ := server.STDConfig()
	clonedConfig, _ := clone.STDConfig()
	second, err := GenerateKeyPair(nil, nil, time.Now, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("certificate reader panic: %v", recovered)
				}
			}()
			for i := 0; i < 1000; i++ {
				for _, config := range []*stdtls.Config{initialConfig, clonedConfig} {
					pair, err := config.GetCertificate(&stdtls.ClientHelloInfo{})
					if err != nil || pair == nil || len(pair.Certificate) != 1 {
						t.Error("invalid concurrent certificate read")
						return
					}
				}
			}
		}()
	}
	for n := 0; n < 1000; n++ {
		if err := UpdateCertificate(server, second); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	for _, config := range []*stdtls.Config{initialConfig, clonedConfig} {
		pair, err := config.GetCertificate(&stdtls.ClientHelloInfo{})
		if err != nil || pair != second {
			t.Fatal("retained config did not observe new key pair")
		}
		if len(config.Certificates) != 0 || len(config.NextProtos) != 2 || config.NextProtos[0] != "h2" {
			t.Fatal("static certificate bypass or ALPN changed")
		}
	}
	if err := (&STDServerConfig{}).UpdateTLSCertificate(second); err == nil {
		t.Fatal("unmanaged TLS config accepted hot update")
	}
}
