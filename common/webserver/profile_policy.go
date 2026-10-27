package webserver

import "time"

// The advertised HTTP/1 policy and the serving engine share these limits.
// HTTP/2 RFC defaults used to omit SETTINGS are defined next to that encoder.
const (
	maxRequestLineBytes   = 8190
	maxHeaderFieldBytes   = 8190
	maxHeaderFields       = 100
	maxRequestHeaderBytes = maxHeaderFields * maxHeaderFieldBytes
	maxHTTP1Requests      = 100
	profileIdleTimeout    = 5 * time.Second
	profileHeaderTimeout  = 10 * time.Second
	profileIOTimeout      = 30 * time.Second
)
