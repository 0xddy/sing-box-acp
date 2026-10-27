package tls

import (
	"crypto/tls"
	"errors"
)

// CertificateUpdater replaces an already parsed key pair. The caller transfers
// ownership of the immutable certificate, including its backing slices.
type CertificateUpdater interface {
	UpdateTLSCertificate(certificate *tls.Certificate) error
}

func (c *STDServerConfig) UpdateTLSCertificate(certificate *tls.Certificate) error {
	if c.inlineCertificate == nil {
		return errors.New("TLS certificate update requires an inline certificate and key")
	}
	c.inlineCertificate.Store(certificate)
	return nil
}

func UpdateCertificate(config ServerConfig, certificate *tls.Certificate) error {
	updater, ok := config.(CertificateUpdater)
	if !ok {
		return errors.New("TLS configuration does not support certificate updates")
	}
	return updater.UpdateTLSCertificate(certificate)
}
