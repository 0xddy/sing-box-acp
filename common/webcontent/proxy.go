package webcontent

import (
	"errors"
	"github.com/sagernet/sing-box/common/webprofile"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
)

func newProxy(options option.WebOptions) (*Site, error) {
	target, err := url.Parse(options.URL)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, MaxIdleConns: 128, MaxIdleConnsPerHost: 32,
		MaxConnsPerHost: 256, IdleConnTimeout: 60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
			// Forwarding headers are removed by ReverseProxy before Rewrite.
			r.SetXForwarded()
		},
		ModifyResponse: func(response *http.Response) error {
			// This listener is the public HTTP server. Do not advertise the
			// backend's server software or transports the listener cannot serve.
			response.Header.Set("Server", webprofile.Server)
			// The public listener supports TCP HTTP/1.1 and HTTP/2 only.
			response.Header.Del("Alt-Svc")
			if raw := response.Header.Get("Location"); raw != "" {
				location, parseErr := url.Parse(raw)
				if parseErr == nil {
					location = response.Request.URL.ResolveReference(location)
					if sameOrigin(location, target) {
						base := strings.TrimSuffix(target.Path, "/")
						if base == "" || location.Path == base || strings.HasPrefix(location.Path, base+"/") {
							// Strip the decoded mount without decoding the remaining path:
							// %2F is part of a segment, not a path separator.
							escaped := location.EscapedPath()
							offset := 0
							for i := 0; i < len(base); i++ {
								if escaped[offset] == '%' {
									offset += 3
								} else {
									offset++
								}
							}
							location.Scheme, location.Host = "", ""
							location.User = nil
							location.Path = strings.TrimPrefix(location.Path, base)
							location.RawPath = escaped[offset:]
							if location.Path == "" {
								location.Path = "/"
							}
							// A leading // would turn a same-site path into a new host.
							if strings.HasPrefix(location.EscapedPath(), "//") {
								location.Path = "/." + location.Path
								location.RawPath = "/." + location.RawPath
							}
						}
						// A redirect outside the configured mount must retain
						// its upstream origin, otherwise the base is added twice.
						response.Header.Set("Location", location.String())
					}
				}
			}

			cookies := response.Header.Values("Set-Cookie")
			response.Header.Del("Set-Cookie")
			for _, raw := range cookies {
				cookie, parseErr := http.ParseSetCookie(raw)
				if parseErr != nil {
					response.Header.Add("Set-Cookie", raw)
					continue
				}
				domain := strings.TrimPrefix(strings.ToLower(cookie.Domain), ".")
				host := strings.ToLower(target.Hostname())
				if domain != "" && (host == domain || strings.HasSuffix(host, "."+domain)) {
					cookie.Domain = ""
				}
				if base := strings.TrimSuffix(target.Path, "/"); base != "" && (cookie.Path == base || strings.HasPrefix(cookie.Path, base+"/")) {
					cookie.Path = strings.TrimPrefix(cookie.Path, base)
					if cookie.Path == "" {
						cookie.Path = "/"
					}
				}
				response.Header.Add("Set-Cookie", cookie.String())
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			apacheError(w, r, proxyErrorStatus(err))
		},
	}
	return &Site{transport: transport, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", webprofile.Server)
		if r.Method == http.MethodOptions && r.URL.Path == "*" {
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodConnect || r.Method == http.MethodTrace {
			w.Header().Set("Allow", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
			if r.Method == http.MethodTrace {
				w.Header().Set("Allow", "")
			}
			apacheError(w, r, http.StatusMethodNotAllowed)
			return
		}
		proxy.ServeHTTP(w, r)
	})}, nil
}

func proxyErrorStatus(err error) int {
	// Like mod_proxy, failure to establish the backend connection is 503;
	// timing out while waiting for the backend response is 504.
	var operation *net.OpError
	if errors.As(err, &operation) && operation.Op == "dial" {
		return http.StatusServiceUnavailable
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

func sameOrigin(left, right *url.URL) bool {
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Hostname(), right.Hostname()) && port(left) == port(right)
}
