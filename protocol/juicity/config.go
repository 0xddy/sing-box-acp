package juicity

import (
	"bytes"
	"crypto/sha256"
	stdtls "crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
)

func quicOptions(o option.QUICOptions) qtls.QUICOptions {
	return qtls.QUICOptions{
		IdleTimeout: o.IdleTimeout.Build(), KeepAlivePeriod: o.KeepAlivePeriod.Build(),
		StreamReceiveWindow:     o.StreamReceiveWindow.Value(),
		ConnectionReceiveWindow: o.ConnectionReceiveWindow.Value(),
		MaxConcurrentStreams:    o.MaxConcurrentStreams, InitialPacketSize: o.InitialPacketSize,
		DisablePathMTUDiscovery: o.DisablePathMTUDiscovery,
	}
}

func validateTLS(min, max string, alpn []string) error {
	if (min != "" && min != "1.3") || (max != "" && max != "1.3") {
		return errors.New("Juicity requires TLS 1.3")
	}
	if len(alpn) != 0 && (len(alpn) != 1 || alpn[0] != "h3") {
		return errors.New("Juicity requires ALPN h3")
	}
	return nil
}

func chainPin(value string) ([]byte, error) {
	for _, decode := range []func(string) ([]byte, error){
		base64.URLEncoding.DecodeString, base64.StdEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString, base64.RawStdEncoding.DecodeString, hex.DecodeString,
	} {
		if pin, err := decode(value); err == nil && len(pin) == sha256.Size {
			return pin, nil
		}
	}
	return nil, errors.New("invalid pinned_certchain_sha256")
}

// Pin the certificate chain as transmitted, including when a TLS session resumes.
type pinnedTLS struct {
	tls.Config
	config *stdtls.Config
}

func (p *pinnedTLS) STDConfig() (*stdtls.Config, error) { return p.config, nil }

func withChainPin(config tls.Config, pin []byte) (tls.Config, error) {
	orig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	cfg := orig.Clone()
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(state stdtls.ConnectionState) error {
		var chain []byte
		for _, cert := range state.PeerCertificates {
			digest := sha256.Sum256(cert.Raw)
			if chain == nil {
				chain = digest[:]
			} else {
				sum := sha256.Sum256(append(chain, digest[:]...))
				chain = sum[:]
			}
		}
		if !bytes.Equal(chain, pin) {
			return errors.New("Juicity certificate chain pin mismatch")
		}
		return nil
	}
	return &pinnedTLS{config, cfg}, nil
}
