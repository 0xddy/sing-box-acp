package webserver

import (
	"net/http"
	"strings"

	"github.com/sagernet/sing-box/common/webprofile"
)

func validateWebsiteRequest(r *http.Request) (int, string) {
	if len(r.Method)+len(r.RequestURI)+len(r.Proto)+2 > maxRequestLineBytes {
		return http.StatusRequestURITooLong, ""
	}
	count := 0
	if r.Host != "" {
		count++
		if len(r.Host)+6 > maxHeaderFieldBytes {
			return http.StatusBadRequest, "Size of a request header field exceeds server limit."
		}
	}
	for name, values := range r.Header {
		count += len(values)
		for _, value := range values {
			if len(name)+len(value)+2 > maxHeaderFieldBytes {
				return http.StatusBadRequest, "Size of a request header field exceeds server limit."
			}
		}
	}
	if count > maxHeaderFields {
		return http.StatusBadRequest, "The number of request header fields exceeds this server's limit."
	}
	if expect := strings.Join(r.Header.Values("Expect"), ", "); expect != "" && !strings.EqualFold(expect, "100-continue") {
		return http.StatusExpectationFailed, webprofile.ExpectationDetail(expect)
	}
	return 0, ""
}
