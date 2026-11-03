package option

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/gofrs/uuid/v5"
	C "github.com/sagernet/sing-box/constant"
)

// ClientCredentials checks the protocol settings and decodes the values used by the QUIC client.
func (o JuicityOutboundOptions) ClientCredentials() (uuid.UUID, []byte, error) {
	if !o.ServerOptions.Build().IsValid() || o.ServerPort == 0 {
		return uuid.Nil, nil, errors.New("Juicity server address and port are required")
	}
	if o.TLS == nil || !o.TLS.Enabled {
		return uuid.Nil, nil, C.ErrTLSRequired
	}
	if err := ValidateJuicityTLS(o.TLS.MinVersion, o.TLS.MaxVersion, o.TLS.ALPN); err != nil {
		return uuid.Nil, nil, err
	}
	id, err := uuid.FromString(o.UUID)
	if err != nil {
		return uuid.Nil, nil, errors.New("invalid Juicity uuid")
	}
	if o.Password == "" {
		return uuid.Nil, nil, errors.New("missing Juicity password")
	}
	switch o.CongestionControl {
	case "", "bbr", "cubic", "new_reno":
	default:
		return uuid.Nil, nil, errors.New("invalid Juicity congestion_control")
	}
	switch o.UDPMode {
	case "", "auto", "stream", "underlay":
	default:
		return uuid.Nil, nil, errors.New("invalid Juicity udp_mode")
	}
	if o.PinnedCertChainSHA256 == "" {
		return id, nil, nil
	}
	if len(o.TLS.CertificatePublicKeySHA256) > 0 || len(o.TLS.Certificate) > 0 || o.TLS.CertificatePath != "" {
		return uuid.Nil, nil, errors.New("pinned_certchain_sha256 conflicts with other certificate trust settings")
	}
	pin, err := chainPin(o.PinnedCertChainSHA256)
	return id, pin, err
}

func (o *JuicityOutboundOptions) validateOutbound() error {
	_, _, err := o.ClientCredentials()
	return err
}

func ValidateJuicityTLS(min, max string, alpn []string) error {
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
