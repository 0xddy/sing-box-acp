package anytls

import (
	stdtls "crypto/tls"

	"github.com/sagernet/sing-box/common/tls"
)

func (h *Inbound) UpdateTLSCertificate(certificate *stdtls.Certificate) error {
	return tls.UpdateCertificate(h.tlsConfig, certificate)
}
