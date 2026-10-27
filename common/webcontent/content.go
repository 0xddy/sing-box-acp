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
	var site *Site
	var err error
	if options.Type == "proxy" {
		site, err = newProxy(options)
	} else {
		site, err = newStatic(options)
	}
	if err != nil {
		return nil, err
	}
	handler := site.Handler
	site.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(&apacheResponseWriter{ResponseWriter: w}, r)
	})
	return site, nil
}

func (s *Site) Close() error {
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
	return nil
}
