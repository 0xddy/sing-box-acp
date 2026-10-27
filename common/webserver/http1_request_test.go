package webserver

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"

	"github.com/sagernet/sing-box/common/webcontent"
	"github.com/sagernet/sing-box/option"
)

func TestRequestProfileBoundaries(t *testing.T) {
	const body = "GET /inside-body HTTP/3.0\r\nHost: body.test\r\nExpect: never-reflect\r\n\r\n\x00"
	for _, chunked := range []bool{false, true} {
		for _, stride := range []int{1, 7, 4096} {
			t.Run(fmt.Sprintf("chunked=%v/stride=%d", chunked, stride), func(t *testing.T) {
				head := "POST / HTTP/3.0\r\nHost: example.test\r\n"
				var framed string
				if chunked {
					head += "Transfer-Encoding: chunked\r\nTrailer: X-Done\r\n\r\n"
					framed = fmt.Sprintf("%x;extension=value\r\n%s\r\n0\r\nX-Done: HTTP/2.0\r\n\r\n", len(body), body)
				} else {
					head += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
					framed = body
				}
				next := "GET /next HTTP/2.0\r\nHost: example.test\r\n\r\n"
				var methods []string
				r := newHTTP1RequestReader(iotest.OneByteReader(strings.NewReader(head+framed+next)), func(req *http.Request) {
					methods = append(methods, req.Method)
				})
				var output bytes.Buffer
				p := make([]byte, stride)
				for {
					n, err := r.Read(p)
					output.Write(p[:n])
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				want := strings.Replace(head, "HTTP/3.0", "HTTP/1.1", 1) + framed + strings.Replace(next, "HTTP/2.0", "HTTP/1.1", 1)
				if output.String() != want || !reflect.DeepEqual(methods, []string{"POST", "GET"}) {
					t.Fatalf("body/trailer/request boundary changed: methods=%v output=%q want=%q", methods, output.String(), want)
				}
			})
		}
	}
}

func TestRequestProfileMalformedFramingAndPreface(t *testing.T) {
	const next = "GET /next HTTP/3.0\r\nHost: example.test\r\n\r\n"
	for name, request := range map[string]string{
		"conflicting-lengths":  "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
		"invalid-length":       "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: -1\r\n\r\n",
		"unsupported-encoding": "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip\r\n\r\n",
		"invalid-chunk":        "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\nz\r\n",
		"invalid-chunk-end":    "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx!!",
		"invalid-version":      "GET / HTTP/3.x\r\nHost: example.test\r\n\r\n",
		"h2-preface":           "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			input := request + next
			r := newHTTP1RequestReader(strings.NewReader(input), func(*http.Request) {})
			actual, err := io.ReadAll(r)
			if err != nil || string(actual) != input {
				t.Fatalf("malformed/opaque stream was reinterpreted: %q, %v", actual, err)
			}
		})
	}
}

func TestProfileVersionProbesAcrossRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		if r.Method == "POST" {
			if _, err := io.Copy(w, r.Body); err != nil {
				t.Error(err)
			}
		} else if _, err := io.WriteString(w, r.URL.Path); err != nil {
			t.Error(err)
		}
	}))
	defer upstream.Close()
	site, err := webcontent.New(option.WebOptions{Type: "proxy", URL: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer site.Close()
	s := startProfileHandler(t, site)
	conn := profileConnection(t, s, "http/1.1")
	reader := bufio.NewReader(conn)
	const payload = "GET /body HTTP/3.0\r\nHost: body.test\r\n\r\n"
	for _, chunked := range []bool{false, true} {
		head := "POST /echo HTTP/3.0\r\nHost: example.test\r\nExpect: 100-continue\r\n"
		if chunked {
			head += "Transfer-Encoding: chunked\r\nTrailer: X-Done\r\n\r\n"
		} else {
			head += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(payload))
		}
		writeProbe(t, conn, head)
		interim := readProfileResponse(t, reader, "POST")
		if interim.StatusCode != 100 {
			t.Fatal("100-continue was lost", interim)
		}
		interim.Body.Close()
		body := payload
		if chunked {
			body = fmt.Sprintf("%x\r\n%s\r\n0\r\nX-Done: yes\r\n\r\n", len(payload), payload)
		}
		writeProbe(t, conn, body+"GET /next HTTP/2.0\r\nHost: example.test\r\n\r\n")
		response := readProfileResponse(t, reader, "POST")
		if got := readProfileBody(t, response); response.StatusCode != 200 || got != payload {
			t.Fatal("normalized request body changed", response.StatusCode, got)
		}
		response = readProfileResponse(t, reader, "GET")
		if got := readProfileBody(t, response); response.StatusCode != 200 || got != "/next" {
			t.Fatal("pipelined version probe failed", response.StatusCode, got)
		}
	}
	// A parser-level error after multiple successful requests must reflect the
	// current Expect value, never a value from an earlier request/body.
	writeProbe(t, conn, "GET / HTTP/1.1\r\nHost: example.test\r\nExpect: <current>&\"'\r\n\r\n")
	response := readProfileResponse(t, reader, "GET")
	if body := readProfileBody(t, response); response.StatusCode != 417 || !strings.Contains(body, "Expect: &lt;current&gt;&amp;&quot;'") || !response.Close {
		t.Fatal("expectation metadata lost or unescaped", response.StatusCode, body)
	}
}

func TestProfileVersionProbeRejectsConflictingLength(t *testing.T) {
	var called atomic.Bool
	s := startProfileHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Store(true) }))
	wire := profileExchange(t, profileConnection(t, s, "http/1.1"), "POST / HTTP/3.0\r\nHost: example.test\r\nContent-Length: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nxx")
	if called.Load() || !strings.Contains(wire, "<h1>") || strings.HasPrefix(wire, "HTTP/1.1 200") {
		t.Fatal("normalization bypassed framing validation", wire)
	}
}

func TestRequestProfileMixedHeaderEnd(t *testing.T) {
	input := "GET / HTTP/3.0\r\nHost: example.test\n\r\nGET /next HTTP/2.0\r\nHost: example.test\r\n\r\n"
	var count int
	r := newHTTP1RequestReader(strings.NewReader(input), func(*http.Request) { count++ })
	output, err := io.ReadAll(r)
	want := strings.NewReplacer("HTTP/3.0", "HTTP/1.1", "HTTP/2.0", "HTTP/1.1").Replace(input)
	if err != nil || string(output) != want || count != 2 {
		t.Fatal("mixed header line endings merged requests", string(output), count, err)
	}
}

func FuzzRequestProfileBodyIsolation(f *testing.F) {
	f.Add([]byte("GET / HTTP/3.0\r\nHost: body\r\n\r\n"), true)
	f.Add([]byte{0, 13, 10, 255}, false)
	f.Fuzz(func(t *testing.T, body []byte, chunked bool) {
		if len(body) > 1<<16 {
			t.Skip("bounded body fixture")
		}
		head := "POST / HTTP/2.0\r\nHost: example.test\r\n"
		var framed string
		if chunked {
			head += "Transfer-Encoding: chunked\r\n\r\n"
			if len(body) > 0 {
				framed = fmt.Sprintf("%x\r\n%s\r\n", len(body), body)
			}
			framed += "0\r\n\r\n"
		} else {
			head += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
			framed = string(body)
		}
		next := "GET / HTTP/3.0\r\nHost: example.test\r\n\r\n"
		r := newHTTP1RequestReader(strings.NewReader(head+framed+next), func(*http.Request) {})
		got, err := io.ReadAll(r)
		want := strings.Replace(head, "HTTP/2.0", "HTTP/1.1", 1) + framed + strings.Replace(next, "HTTP/3.0", "HTTP/1.1", 1)
		if err != nil || string(got) != want {
			t.Fatal("body or following request corrupted", err)
		}
	})
}

func TestProfileRangeErrorPersistentConnections(t *testing.T) {
	s := newProfileServer(t)
	conn := profileConnection(t, s, "http/1.1")
	reader := bufio.NewReader(conn)
	writeProbe(t, conn, "GET / HTTP/1.1\r\nHost: example.test\r\nRange: bytes=9999-\r\n\r\nGET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	response := readProfileResponse(t, reader, "GET")
	if body := readProfileBody(t, response); response.StatusCode != 416 || !strings.Contains(body, "<h1>Requested Range Not Satisfiable</h1>") || response.ContentLength != -1 || response.Header.Get("Content-Range") != "" || !reflect.DeepEqual(response.TransferEncoding, []string{"chunked"}) {
		t.Fatal("persistent range error framing", response, body)
	}
	response = readProfileResponse(t, reader, "GET")
	if body := readProfileBody(t, response); response.StatusCode != 200 || body != referenceContent {
		t.Fatal("range error corrupted next response", response, body)
	}
}

func TestProfilePartialPipelinedRequest(t *testing.T) {
	s := newProfileServer(t)
	conn := profileConnection(t, s, "http/1.1")
	reader := bufio.NewReader(conn)
	writeProbe(t, conn, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\nG")
	response := readProfileResponse(t, reader, "GET")
	if body := readProfileBody(t, response); response.StatusCode != 200 || body != referenceContent {
		t.Fatal("first response blocked on next request", body)
	}
	writeProbe(t, conn, "ET / HTTP/3.0\r\nHost: example.test\r\nConnection: close\r\n\r\n")
	response = readProfileResponse(t, reader, "GET")
	if body := readProfileBody(t, response); response.StatusCode != 200 || body != referenceContent {
		t.Fatal("background read lost the request prefix", body)
	}
}
