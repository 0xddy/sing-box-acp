package webcontent

import (
	"github.com/sagernet/sing-box/common/webprofile"
	"net/http"
)

const staticAllow = "OPTIONS,HEAD,GET,POST"

// Normalize at commit time as ReverseProxy adds response headers, including
// interim 1xx responses, after entering the handler. Unwrap preserves streaming
// and protocol upgrades through http.ResponseController.
type apacheResponseWriter struct {
	http.ResponseWriter
}

func (w *apacheResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *apacheResponseWriter) WriteHeader(status int) {
	w.Header().Set("Server", webprofile.Server)
	w.ResponseWriter.WriteHeader(status)
}

func (w *apacheResponseWriter) Write(p []byte) (int, error) {
	w.Header().Set("Server", webprofile.Server)
	return w.ResponseWriter.Write(p)
}

// Apache's core recognizes these methods even when a resource has no handler
// for them. Unknown extension methods on a static resource receive 501, not 405.
func knownMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
		"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
		"VERSION-CONTROL", "CHECKOUT", "UNCHECKOUT", "CHECKIN", "UPDATE", "LABEL",
		"REPORT", "MKWORKSPACE", "MKACTIVITY", "BASELINE-CONTROL", "MERGE":
		return true
	default:
		return false
	}
}

func apacheError(w http.ResponseWriter, r *http.Request, status int) {
	webprofile.WriteError(w, r, status, "")
}

// contentResponseWriter converts only errors generated locally by ServeContent.
// Proxied application responses must keep their own bodies and status codes.
type contentResponseWriter struct {
	http.ResponseWriter
	request  *http.Request
	rejected bool
}

func (w *contentResponseWriter) WriteHeader(status int) {
	if status >= 400 {
		w.rejected = true
		apacheError(w.ResponseWriter, w.request, status)
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *contentResponseWriter) Write(p []byte) (int, error) {
	if w.rejected {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}
