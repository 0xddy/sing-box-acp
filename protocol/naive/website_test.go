package naive_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/option"
	"golang.org/x/net/http2"
)

func TestWebsiteNeverForwardsProxyCredentialsOrConnectTargets(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			var visits atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				visits.Add(1)
				for _, header := range []string{"Proxy-Authorization", "Padding", "Padding-Type-Request", "Proxy-Connection"} {
					if r.Header.Get(header) != "" {
						t.Errorf("proxy-only header reached website: %s", header)
					}
				}
				_, _ = io.WriteString(w, "configured website")
			}))
			defer backend.Close()
			_, address, cfg, router := fixtureWithWeb(t, &option.WebOptions{Type: "proxy", URL: backend.URL})
			var transport http.RoundTripper
			if protocol == "h2" {
				h := &http2.Transport{TLSClientConfig: cfg}
				transport = h
				defer h.CloseIdleConnections()
			} else {
				h := &http3.Transport{TLSClientConfig: cfg}
				transport = h
				defer h.Close()
			}
			client := &http.Client{Transport: transport}
			for _, probe := range []struct {
				method, credentials, padding string
				status                       int
			}{
				{"GET", "a:one", "present", 200},
				{"CONNECT", "a:wrong", "present", 405},
				{"CONNECT", "", "present", 405},
				{"CONNECT", "a:one", "", 405},
			} {
				req, _ := http.NewRequest(probe.method, "https://"+address+"/", nil)
				req.Host = "untrusted-target.invalid:443"
				req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(probe.credentials)))
				if probe.padding != "" {
					req.Header.Set("Padding", probe.padding)
				}
				req.Header.Set("Padding-Type-Request", "1")
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != probe.status || response.Header.Get("Padding") != "" || response.Header.Get("Proxy-Authenticate") != "" {
					t.Fatalf("website response %s: %d %v", probe.method, response.StatusCode, err)
				}
				if probe.status == 200 && string(body) != "configured website" {
					t.Fatal("wrong website target")
				}
			}
			if visits.Load() != 1 || router.routed.Load() != 0 {
				t.Fatal("unauthenticated CONNECT reached a target or accounting")
			}
		})
	}
}
