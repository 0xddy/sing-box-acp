package v2rayxhttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestPacketSessionReorderAndClose(t *testing.T) {
	var r sessions
	s, _ := r.get("client")
	defer r.close()
	for _, packet := range []struct {
		seq   uint64
		value string
	}{{2, "CC"}, {2, "CC"}, {0, "AA"}, {1, "BB"}} {
		if err := s.push(packet.seq, []byte(packet.value), 3); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.push(5, []byte("outside window"), 3); err == nil {
		t.Fatal("accepted packet outside reorder window")
	}
	if !s.attachDownload() || s.attachDownload() {
		t.Fatal("duplicate download")
	}
	s.finish(true) // successful pairing wins against a running expiry timer.
	var data [6]byte
	if _, err := io.ReadFull(s, data[:]); err != nil || string(data[:]) != "AABBCC" {
		t.Fatal(string(data[:]), err)
	}
	if r.buffered.Load() != 0 {
		t.Fatal("retained buffered bytes")
	}
	done := make(chan error, 1)
	go func() { _, err := s.Read(data[:]); done <- err }()
	r.close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("session reader blocked after shutdown")
	}
	if _, err := r.get("late"); err == nil {
		t.Fatal("closed listener accepted session")
	}
}

func TestUnpairedSessionsExpire(t *testing.T) {
	var r sessions
	s, _ := r.get("orphan")
	if err := s.push(1, []byte("pending"), 4); err != nil {
		t.Fatal(err)
	}
	s.finish(true)
	replacement, _ := r.get("orphan")
	defer r.close()
	if s == replacement || r.buffered.Load() != 0 {
		t.Fatal("expired session retained packets or session ID")
	}
}

func TestSplitDownloadHalfCloseAllowsUploadTail(t *testing.T) {
	for _, mode := range []string{ModeStreamUp, ModePacketUp} {
		t.Run(mode, func(t *testing.T) {
			gotTail := make(chan string, 1)
			h := handlerFunc(func(_ context.Context, c net.Conn, _, _ M.Socksaddr, close N.CloseHandlerFunc) {
				defer close(nil)
				c.SetDeadline(time.Now().Add(3 * time.Second))
				c.Write([]byte("reply"))
				c.(N.WriteCloser).CloseWrite()
				tail := make([]byte, 4)
				io.ReadFull(c, tail)
				gotTail <- string(tail)
			})
			s := testServer(t, Options{Mode: mode}, h)
			srv := httptest.NewUnstartedServer(s)
			srv.EnableHTTP2 = true
			srv.StartTLS()
			defer srv.Close()
			defer s.sessions.close()
			client := srv.Client()
			client.Timeout = 3 * time.Second
			get, _ := http.NewRequest("GET", srv.URL+"/session", nil)
			s.codec.applyPaddingToRequest(get)
			response, err := client.Do(get)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(reply) != "reply" {
				t.Fatal("download EOF", string(reply), err)
			}
			path := "/session"
			if mode == ModePacketUp {
				path += "/0"
			}
			put, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader("tail"))
			s.codec.applyPaddingToRequest(put)
			response, err = client.Do(put)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatal("upload after EOF", response.Status)
			}
			select {
			case v := <-gotTail:
				if v != "tail" {
					t.Fatalf("tail = %q", v)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("upload tail lost")
			}
		})
	}
}

func TestXHTTPOptionRoundTrip(t *testing.T) {
	const config = `{"type":"xhttp","mode":"packet-up","host":"proxy.example","path":"/a/?token=abc","x_padding_bytes":[120,300],"sc_max_each_post_bytes":"8192","sc_min_posts_interval_ms":0,"xmux":{"max_connections":3,"h_max_request_times":"10-20"}}`
	var transport option.V2RayTransportOptions
	if err := json.Unmarshal([]byte(config), &transport); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(transport)
	if err != nil {
		t.Fatal(err)
	}
	var decoded option.V2RayTransportOptions
	if err = json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	opts := decoded.XHTTPOptions
	if opts.XPaddingBytes.From != 120 || opts.XPaddingBytes.To != 300 || opts.Xmux.HMaxRequestTimes.To != 20 || opts.ScMinPostsIntervalMs.To != 0 {
		t.Fatal(string(b))
	}
	for _, input := range []string{`{"type":"xhttp","unexpected":true}`, `{"type":"xhttp","x_padding_bytes":"30-10"}`, `{"type":"xhttp","x_padding_bytes":[1,2,3]}`} {
		if json.Unmarshal([]byte(input), &decoded) == nil {
			t.Fatal("accepted", input)
		}
	}
}

func TestMalformedPacketChunks(t *testing.T) {
	c := newCodec(Options{UplinkDataPlacement: PlacementHeader})
	for _, bad := range []http.Header{{"X-Data-0": {"%%%"}}, {"X-Data-2": {"YQ"}}, {"X-Data-0": {"YQ", "YQ"}}} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header = bad
		if _, err := c.decodeUplinkPayload(r, nil); err == nil {
			t.Fatal("accepted malformed chunks", bad)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Data-0", "YQ")
	b, err := c.decodeUplinkPayload(r, nil)
	if err != nil || !bytes.Equal(b, []byte("a")) {
		t.Fatal(b, err)
	}
}

func TestXMUXRollsPoolWithoutAbortingActiveStreams(t *testing.T) {
	one := &Range{From: 1, To: 1}
	g := newMuxGroup(context.Background(), &option.XHTTPMuxOptions{MaxConnections: one, CMaxReuseTimes: one}, nil)
	defer g.cancel()
	a, b := g.acquire(), g.acquire()
	if a == b {
		t.Fatal("exhausted connection was reused")
	}
	g.release(b)
	g.release(a)
	if len(g.pools) != 0 {
		t.Fatal("retired transports were retained")
	}
}
