package webcontent

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestStaticHTTPBehavior(t *testing.T) {
	const content = " \n<!doctype html><html><head><style>body { color: navy; }</style></head><body><h1>自定义页面</h1><script>document.title = 'Example';</script></body></html>\n "
	site, err := New(option.WebOptions{Type: "static", Content: content})
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	request := func(method, path string, headers map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		site.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/", "/about", "/nested/page?query=1", "/favicon.svg"} {
		if got := request("GET", path, nil); got.Code != 200 || got.Body.String() != content || got.Header().Get("Content-Type") != "text/html; charset=utf-8" {
			t.Fatalf("%s: %d", path, got.Code)
		}
	}
	page := request("GET", "/about", nil)
	if got := request("HEAD", "/about", nil); got.Code != 200 || got.Body.Len() != 0 || got.Header().Get("Content-Length") != page.Header().Get("Content-Length") {
		t.Fatal("HEAD representation differs")
	}
	if got := request("GET", "/about", map[string]string{"If-None-Match": page.Header().Get("ETag")}); got.Code != 304 || got.Body.Len() != 0 {
		t.Fatal("ETag revalidation failed")
	}
	if got := request("GET", "/about", map[string]string{"Range": "bytes=0-9", "Accept-Encoding": "gzip"}); got.Code != 206 || got.Body.Len() != 10 || got.Header().Get("Content-Encoding") != "" {
		t.Fatal("range failed")
	}
	encoded := request("GET", "/about", map[string]string{"Accept-Encoding": "gzip"})
	z, err := gzip.NewReader(encoded.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	decoded, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != page.Body.String() || encoded.Header().Get("ETag") == page.Header().Get("ETag") {
		t.Fatal("gzip representation failed")
	}
	if got := request("POST", "/", nil); got.Code != 405 || got.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal("method semantics failed")
	}
	if request("GET", "/", map[string]string{"Accept-Encoding": "gzip;q=0,*;q=1"}).Header().Get("Content-Encoding") != "" {
		t.Fatal("gzip exclusion ignored")
	}
}

func TestProxyFixedTargetAndResponses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/base/page" || r.Header.Get("X-Forwarded-Host") != "public.example" {
			t.Errorf("unexpected request %s %s %s", r.Host, r.URL.Path, r.Header.Get("X-Forwarded-Host"))
		}
		w.Header().Set("X-Upstream-Host", r.Host)
		redirect := r.Header.Get("X-Test-Location")
		if redirect == "" {
			w.Header().Set("Location", "http://"+r.Host+"/base/next?q=1")
		} else {
			w.Header().Set("Location", redirect)
		}
		w.Header().Set("Set-Cookie", "sid=1; Domain=127.0.0.1; Path=/base/; HttpOnly")
		w.Header().Set("Alt-Svc", `h3=":443"`)
		w.WriteHeader(302)
	}))
	defer upstream.Close()
	site, err := New(option.WebOptions{Type: "proxy", URL: upstream.URL + "/base"})
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	r := httptest.NewRequest("GET", "https://public.example/page", nil)
	r.Header.Set("X-Forwarded-Host", "attacker.example")
	w := httptest.NewRecorder()
	site.ServeHTTP(w, r)
	if w.Code != 302 || w.Header().Get("Location") != "/next?q=1" || strings.Contains(w.Header().Get("Set-Cookie"), "Domain=") || !strings.Contains(w.Header().Get("Set-Cookie"), "Path=/;") || w.Header().Get("Alt-Svc") != "" || w.Header().Get("X-Upstream-Host") != strings.TrimPrefix(upstream.URL, "http://") {
		t.Fatalf("response: %v", w.Result())
	}
	for _, tc := range []struct{ location, want string }{
		{"/base/next", "/next"}, {"next", "/next"},
		{"/base/a%2Fb", "/a%2Fb"}, {"/base/%2Fevil.example", "/%2Fevil.example"},
		{"/base//evil.example", "/.//evil.example"},
		{"/outside", upstream.URL + "/outside"}, {"https://other.example/", "https://other.example/"},
	} {
		t.Run(tc.location, func(t *testing.T) {
			request := r.Clone(r.Context())
			request.Header.Set("X-Test-Location", tc.location)
			got := httptest.NewRecorder()
			site.ServeHTTP(got, request)
			if got.Header().Get("Location") != tc.want {
				t.Fatalf("redirect = %q, want %q", got.Header().Get("Location"), tc.want)
			}
		})
	}
	upstream.Close()
	w = httptest.NewRecorder()
	site.ServeHTTP(w, r)
	if w.Code != 502 {
		t.Fatalf("upstream failure: %d", w.Code)
	}
}

func TestConstructorRejectsInvalidConfiguration(t *testing.T) {
	if _, err := New(option.WebOptions{Type: "unknown"}); err == nil {
		t.Fatal("constructor skipped option validation")
	}
}
