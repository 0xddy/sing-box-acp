// Package webprofile defines the shared Apache response presentation without
// depending on website content, proxy options, or connection serving.
package webprofile

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// The website uses a consistent Apache 2.4 response profile:
// ServerTokens Prod, ServerSignature Off and TraceEnable Off. This does not
// replace Go's request parser, HTTP/2 engine or TLS implementation. webserver
// also normalizes HTTP/1 presentation and initial HTTP/2 settings on the wire.
// References: https://httpd.apache.org/docs/2.4/mod/core.html and the canned
// response layout in Apache httpd's modules/http/http_protocol.c (Apache-2.0).
const Server = "Apache"

// Apache's ap_escape_html2 escapes &, <, > and double quotes, leaving single
// quotes unchanged. Reflect only the parsed header value, never raw header text.
func ExpectationDetail(value string) string {
	if value == "" {
		return ""
	}
	escaped := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;").Replace(value)
	return "The client sent<pre>\n    Expect: " + escaped + "\n</pre>\n"
}

// ErrorPage formats locally generated errors, including parser rejections at
// the website connection boundary. detail must be an already escaped note.
func ErrorPage(status int, method, detail string) (string, string) {
	title := http.StatusText(status)
	var message string
	switch status {
	case http.StatusBadRequest:
		message = "<p>Your browser sent a request that this server could not understand.<br />\n" + detail + "</p>\n"
	case http.StatusRequestURITooLong:
		title = "Request-URI Too Long"
		message = "<p>The requested URL's length exceeds the capacity\nlimit for this server.<br />\n</p>\n"
	case http.StatusHTTPVersionNotSupported:
		message = "<p>The server does not support the HTTP protocol version used in your request.</p>\n"
	case http.StatusExpectationFailed:
		message = "<p>The expectation given in the Expect request-header\nfield could not be met by this server.\n" + detail + "</p><p>Only the 100-continue expectation is supported.</p>\n"
	case http.StatusMethodNotAllowed:
		message = "<p>The requested method " + html.EscapeString(method) + " is not allowed for this URL.</p>\n"
	case http.StatusNotImplemented:
		message = "<p>" + html.EscapeString(method) + " not supported for current URL.<br />\n</p>\n"
	case http.StatusPreconditionFailed:
		message = "<p>The precondition on the request for this URL evaluated to false.</p>\n"
	case http.StatusRequestedRangeNotSatisfiable:
		title = "Requested Range Not Satisfiable"
		message = "<p>None of the range-specifier values in the Range\nrequest-header field overlap the current extent\nof the selected resource.</p>\n"
	case http.StatusBadGateway:
		message = "<p>The proxy server received an invalid\r\nresponse from an upstream server.<br />\r\n</p>\n"
	case http.StatusServiceUnavailable:
		message = "<p>The server is temporarily unable to service your\nrequest due to maintenance downtime or capacity\nproblems. Please try again later.</p>\n"
	case http.StatusGatewayTimeout:
		message = "<p>The gateway did not receive a timely response\nfrom the upstream server or application.</p>\n"
	default:
		message = "<p>The server encountered an internal error and was unable to complete your request.</p>\n"
	}
	body := fmt.Sprintf("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n<html><head>\n<title>%d %s</title>\n</head><body>\n<h1>%s</h1>\n%s</body></html>\n", status, title, title, message)
	return title, body
}

// WriteError applies the same profile to HTTP-layer validation failures.
func WriteError(w http.ResponseWriter, r *http.Request, status int, detail string) {
	_, body := ErrorPage(status, r.Method, detail)
	h := w.Header()
	// Discard representation headers left by ServeContent before it discovered
	// a failed precondition or range.
	for _, name := range []string{"Content-Encoding", "Content-Length", "Content-Range", "ETag", "Last-Modified", "Accept-Ranges", "Cache-Control", "Vary", "X-Content-Type-Options"} {
		h.Del(name)
	}
	h.Set("Server", Server)
	h.Set("Content-Type", "text/html; charset=iso-8859-1")
	flush := status == http.StatusRequestedRangeNotSatisfiable || (status == http.StatusExpectationFailed && r.Method == http.MethodHead)
	if !flush {
		h.Set("Content-Length", strconv.Itoa(len(body)))
	} else if r.ProtoMajor == 1 && r.Close {
		// net/http removes the identity token and closes after the body.
		// Apache uses close delimiting when this response cannot stay alive.
		h.Set("Transfer-Encoding", "identity")
	}
	w.WriteHeader(status)
	if flush {
		// Commit without net/http synthesizing Content-Length. Persistent
		// HTTP/1 uses chunks, HTTP/2 uses END_STREAM, and closing HTTP/1 uses EOF.
		if err := http.NewResponseController(w).Flush(); err != nil {
			return // A disconnected client cannot receive the error body.
		}
	}
	if r.Method != http.MethodHead {
		// A disconnected client cannot receive another response; net/http owns
		// closing the connection and the caller has no recovery action here.
		_, _ = io.WriteString(w, body)
	}
}
