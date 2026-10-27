package webcontent

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func TestApacheStaticResponses(t *testing.T) {
	site, err := New(option.WebOptions{Type: "static", Content: "hello world"})
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	request := func(method string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://example.com/", nil)
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		w := httptest.NewRecorder()
		site.ServeHTTP(w, r)
		return w
	}
	page := request("GET", nil)
	etag := page.Header().Get("ETag")
	if !regexp.MustCompile(`^"b-[0-9a-f]+"$`).MatchString(etag) {
		t.Fatalf("not an Apache size-mtime ETag: %s", etag)
	}
	if page.Header().Get("Cache-Control") != "" {
		t.Fatal("unexpected forced cache lifetime")
	}
	modified, err := http.ParseTime(page.Header().Get("Last-Modified"))
	if err != nil {
		t.Fatal(err)
	}
	stamp, err := strconv.ParseInt(strings.TrimSuffix(strings.Split(etag, "-")[1], `"`), 16, 64)
	if err != nil || !time.UnixMicro(stamp).Truncate(time.Second).Equal(modified) {
		t.Fatal("ETag mtime and Last-Modified disagree", err)
	}
	for _, tc := range []struct {
		name, method string
		headers      map[string]string
		status       int
		errorText    string
	}{
		{"get", "GET", nil, 200, ""},
		{"head", "HEAD", nil, 200, ""},
		{"options", "OPTIONS", nil, 200, ""},
		{"post", "POST", nil, 200, ""},
		{"trace-disabled", "TRACE", nil, 405, "The requested method TRACE is not allowed for this URL."},
		{"connect", "CONNECT", nil, 405, "The requested method CONNECT is not allowed for this URL."},
		{"unknown-method", "BREW", nil, 501, "BREW not supported for current URL."},
		{"case-sensitive-method", "get", nil, 501, "get not supported for current URL."},
		{"not-modified", "GET", map[string]string{"If-None-Match": etag}, 304, ""},
		{"weak-not-modified", "GET", map[string]string{"If-None-Match": "W/" + etag}, 304, ""},
		{"modified-since", "GET", map[string]string{"If-Modified-Since": page.Header().Get("Last-Modified")}, 304, ""},
		{"range", "GET", map[string]string{"Range": "bytes=0-4"}, 206, ""},
		{"precondition", "GET", map[string]string{"If-Match": `"different"`, "Accept-Encoding": "gzip"}, 412, "The precondition on the request for this URL evaluated to false."},
		{"head-precondition", "HEAD", map[string]string{"If-Match": `"different"`}, 412, ""},
		{"unsatisfied-range", "GET", map[string]string{"Range": "bytes=1000-"}, 416, "None of the range-specifier values"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(tc.method, tc.headers)
			if w.Code != tc.status || w.Header().Get("Server") != "Apache" {
				t.Fatalf("status=%d headers=%v", w.Code, w.Header())
			}
			if tc.method == "HEAD" || tc.status == 304 || tc.method == "OPTIONS" {
				if w.Body.Len() != 0 {
					t.Fatal("body on a bodyless response")
				}
			}
			if tc.status >= 400 {
				if w.Header().Get("Content-Type") != "text/html; charset=iso-8859-1" {
					t.Fatal("non-Apache error content type", w.Header())
				}
				for _, name := range []string{"ETag", "Last-Modified", "Content-Encoding", "X-Content-Type-Options"} {
					if w.Header().Get(name) != "" {
						t.Fatalf("representation or Go error header leaked: %s", name)
					}
				}
				length, err := strconv.Atoi(w.Header().Get("Content-Length"))
				if tc.status != 416 && (err != nil || length <= 0 || (tc.method != "HEAD" && length != w.Body.Len())) {
					t.Fatal("invalid error Content-Length")
				}
			}
			if tc.errorText != "" {
				body := w.Body.String()
				if !strings.HasPrefix(body, `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"`) ||
					!strings.Contains(body, fmt.Sprintf("<title>%d ", tc.status)) ||
					!strings.Contains(body, tc.errorText) || strings.Contains(body, "<address>") {
					t.Fatalf("unexpected Apache error page: %s", body)
				}
			}
			if tc.status == 416 && (w.Header().Get("Content-Range") != "" || w.Header().Get("Content-Length") != "") {
				t.Fatal("range error differs from Apache framing")
			}
			if tc.status == 405 || tc.status == 501 || tc.method == "OPTIONS" {
				allow := "OPTIONS,HEAD,GET,POST"
				if tc.method == "TRACE" {
					allow = ""
				}
				if w.Header().Get("Allow") != allow {
					t.Fatal("unexpected core Allow methods", w.Header())
				}
			}
		})
	}
	if small := request("GET", map[string]string{"Accept-Encoding": "gzip"}); small.Header().Get("Content-Encoding") != "" || small.Header().Get("Vary") != "" {
		t.Fatal("mod_deflate does not compress very small responses")
	}
	const largeContent = "hello world hello world hello world hello world hello world hello world"
	largeSite, err := New(option.WebOptions{Type: "static", Content: largeContent})
	if err != nil {
		t.Fatal(err)
	}
	defer largeSite.Close()
	site = largeSite
	etag = request("GET", nil).Header().Get("ETag")
	encoded := request("GET", map[string]string{"Accept-Encoding": "gzip"})
	if encoded.Header().Get("ETag") != strings.TrimSuffix(etag, `"`)+`-gzip"` || encoded.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatal("mod_deflate representation headers differ")
	}
	if !bytes.HasPrefix(encoded.Body.Bytes(), []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3}) {
		t.Fatal("gzip header differs from mod_deflate")
	}
	z, err := gzip.NewReader(encoded.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	decoded, err := io.ReadAll(z)
	if err != nil || string(decoded) != largeContent {
		t.Fatal("gzip response corrupted", err)
	}
}

func TestApacheProxyResponses(t *testing.T) {
	var seen int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		w.Header().Add("Server", "nginx/1.28")
		w.Header().Add("Server", "backend")
		w.Header().Set("Alt-Svc", `h3=":443"`)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"app-etag"`)
		w.Header().Set("Set-Cookie", "sid=1; HttpOnly")
		w.WriteHeader(http.StatusNotFound)
		// A failed test-client write needs no retry.
		_, _ = io.WriteString(w, `{"error":"application response"}`)
	}))
	defer upstream.Close()
	site, err := New(option.WebOptions{Type: "proxy", URL: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	for _, method := range []string{"TRACE", "CONNECT", "OPTIONS"} {
		r := httptest.NewRequest(method, "https://example.com/", nil)
		status := 405
		if method == "OPTIONS" {
			r.URL.Path = "*"
			r.RequestURI = "*"
			status = 200
		}
		w := httptest.NewRecorder()
		site.ServeHTTP(w, r)
		if w.Code != status || w.Header().Get("Server") != "Apache" || seen != 0 {
			t.Fatalf("%s reached backend or wrong response: %d %v", method, w.Code, w.Header())
		}
	}
	w := httptest.NewRecorder()
	site.ServeHTTP(w, httptest.NewRequest("GET", "https://example.com/", nil))
	if headers := w.Header().Values("Server"); len(headers) != 1 || headers[0] != "Apache" {
		t.Fatal("backend server identity leaked", headers)
	}
	if w.Code != 404 || w.Body.String() != `{"error":"application response"}` || w.Header().Get("ETag") != `"app-etag"` || w.Header().Get("Set-Cookie") == "" || w.Header().Get("Alt-Svc") != "" {
		t.Fatal("backend application semantics changed", w)
	}
	upstream.Close()
	for _, method := range []string{"GET", "HEAD"} {
		w = httptest.NewRecorder()
		site.ServeHTTP(w, httptest.NewRequest(method, "https://example.com/", nil))
		if w.Code != 503 || w.Header().Get("Server") != "Apache" || w.Header().Get("Content-Type") != "text/html; charset=iso-8859-1" {
			t.Fatal("backend connection failure profile", w)
		}
		if method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("HEAD error contains a body")
		}
	}
}

func TestProxyErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{
		{&net.OpError{Op: "dial", Err: errors.New("refused")}, 503},
		{&net.OpError{Op: "dial", Err: context.DeadlineExceeded}, 503},
		{fmt.Errorf("wrapped: %w", context.DeadlineExceeded), 504},
		{errors.New("malformed upstream HTTP response"), 502},
	} {
		if got := proxyErrorStatus(tc.err); got != tc.status {
			t.Fatalf("%v: %d, want %d", tc.err, got, tc.status)
		}
	}
}
