// Package webcontent builds HTTP handlers independently of TLS and proxy protocols.
package webcontent

import (
	"net/http"

	"github.com/sagernet/sing-box/option"
)

type Site struct {
	http.Handler
	transport *http.Transport
}

func New(options option.WebOptions) (*Site, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if options.Type == "proxy" {
		return newProxy(options)
	}
	return newStatic(options)
}

func (s *Site) Close() error {
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
	return nil
}
