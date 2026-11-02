package v2rayxhttp

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/sagernet/sing-box/common/tls"

	"golang.org/x/net/http/httpguts"
)

func normalizeOptions(o Options, config tls.Config) (Options, error) {
	if config == nil {
		return o, fmt.Errorf("XHTTP requires TLS or REALITY")
	}
	if alpn := config.NextProtos(); len(alpn) > 0 && alpn[0] != "h2" {
		return o, fmt.Errorf("XHTTP requires h2 as the first ALPN protocol")
	}
	if o.Mode == "" {
		o.Mode = ModeAuto
	}
	switch o.Mode {
	case ModeAuto, ModePacketUp, ModeStreamUp, ModeStreamOne:
	default:
		return o, fmt.Errorf("unsupported XHTTP mode %q", o.Mode)
	}
	if _, err := endpointURL(o.Host, o.Path); err != nil {
		return o, err
	}
	if o.DownloadSettings != nil {
		if o.Mode == ModeStreamOne {
			return o, fmt.Errorf("download_settings requires a split XHTTP mode")
		}
		if _, err := endpointURL(o.DownloadSettings.Host, o.DownloadSettings.Path); err != nil {
			return o, err
		}
	}
	o.Method = strings.ToUpper(o.Method)
	if o.Method == "" {
		o.Method = http.MethodPost
	}
	if !httpguts.ValidHeaderFieldName(o.Method) {
		return o, fmt.Errorf("invalid XHTTP uplink_http_method %q", o.Method)
	}
	if o.Method == http.MethodGet && (o.Mode != ModePacketUp || (o.UplinkDataPlacement != PlacementHeader && o.UplinkDataPlacement != PlacementCookie)) {
		return o, fmt.Errorf("GET uploads require packet-up with header or cookie payloads")
	}
	in := func(value string, choices ...string) bool {
		for _, v := range choices {
			if value == v {
				return true
			}
		}
		return false
	}
	for _, p := range []string{o.SessionPlacement, o.SeqPlacement} {
		if !in(p, "", PlacementPath, PlacementQuery, PlacementHeader, PlacementCookie) {
			return o, fmt.Errorf("invalid XHTTP metadata placement %q", p)
		}
	}
	if !in(o.UplinkDataPlacement, "", PlacementBody, PlacementAuto, PlacementHeader, PlacementCookie) {
		return o, fmt.Errorf("invalid XHTTP uplink_data_placement %q", o.UplinkDataPlacement)
	}
	if (o.UplinkDataPlacement == PlacementHeader || o.UplinkDataPlacement == PlacementCookie) && o.Mode != ModePacketUp && o.Mode != ModeAuto {
		return o, fmt.Errorf("header/cookie payloads require packet-up")
	}
	if o.XPaddingPlacement == "queryInHeader" {
		o.XPaddingPlacement = PlacementQueryInHeader
	}
	if !in(o.XPaddingPlacement, "", PlacementCookie, PlacementQuery, PlacementHeader, PlacementQueryInHeader) || !in(o.XPaddingMethod, "", PaddingMethodRepeatX, PaddingMethodTokenish) {
		return o, fmt.Errorf("invalid XHTTP padding placement or method")
	}
	if o.XPaddingObfsMode && o.XPaddingPlacement == "" {
		o.XPaddingPlacement = PlacementQueryInHeader
	}
	for k, values := range o.Headers {
		if !httpguts.ValidHeaderFieldName(k) || strings.EqualFold(k, "Host") {
			return o, fmt.Errorf("invalid XHTTP header %q (use host for the authority)", k)
		}
		for _, v := range values {
			if !httpguts.ValidHeaderFieldValue(v) {
				return o, fmt.Errorf("invalid value for XHTTP header %q", k)
			}
		}
	}
	for _, k := range []string{o.SessionKey, o.SeqKey, o.XPaddingKey, o.XPaddingHeader, o.UplinkDataKey} {
		if k != "" && !httpguts.ValidHeaderFieldName(k) {
			return o, fmt.Errorf("invalid XHTTP metadata key %q", k)
		}
	}
	if o.ServerMaxHeaderBytes < 0 || o.ServerMaxHeaderBytes > 4<<20 || o.ScMaxBufferedPosts < 0 || o.ScMaxBufferedPosts > 4096 {
		return o, fmt.Errorf("invalid XHTTP server buffer limit")
	}
	for _, limit := range []struct {
		name     string
		r        *Range
		min, max int32
	}{
		{"x_padding_bytes", o.XPaddingBytes, 1, 65536}, {"sc_max_each_post_bytes", o.ScMaxEachPostBytes, 1, 16 << 20}, {"sc_min_posts_interval_ms", o.ScMinPostsIntervalMs, 0, 600000}, {"sc_stream_up_server_secs", o.ScStreamUpServerSecs, 0, 86400}, {"uplink_chunk_size", o.UplinkChunkSize, 1, 1 << 20}, {"session_length", o.SessionIDLength, 1, 256},
	} {
		if r := limit.r; r != nil && (r.From < limit.min || r.To < r.From || r.To > limit.max) {
			return o, fmt.Errorf("XHTTP %s must be between %d and %d", limit.name, limit.min, limit.max)
		}
	}
	if (o.SessionIDTable == "") != (o.SessionIDLength == nil) {
		return o, fmt.Errorf("set session_table and session_length together")
	}
	if o.SessionIDTable != "" {
		alphabet := o.SessionIDTable
		if known, ok := PredefinedTable[alphabet]; ok {
			alphabet = known
		}
		chars := make(map[rune]bool)
		for _, r := range alphabet {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '~') {
				return o, fmt.Errorf("invalid session_table character %q", r)
			}
			if chars[r] {
				return o, fmt.Errorf("duplicate character in session_table")
			}
			chars[r] = true
		}
		if math.Log2(float64(len(chars)))*float64(o.SessionIDLength.From) <= 31 {
			return o, fmt.Errorf("XHTTP session ID space is too small")
		}
	}
	if m := o.Xmux; m != nil {
		if m.MaxConnections != nil && m.MaxConcurrency != nil && m.MaxConnections.To > 0 && m.MaxConcurrency.To > 0 {
			return o, fmt.Errorf("XHTTP xmux max_connections and max_concurrency are mutually exclusive")
		}
		for _, r := range []*Range{m.MaxConnections, m.MaxConcurrency, m.CMaxReuseTimes, m.HMaxRequestTimes, m.HMaxReusableSecs} {
			if r != nil && (r.From < 0 || r.To < r.From) {
				return o, fmt.Errorf("invalid XHTTP xmux range")
			}
		}
	}
	meta := newCodec(o)
	if meta.sessionPlacement == meta.seqPlacement && meta.sessionPlacement != PlacementPath && strings.EqualFold(meta.sessionKey, meta.seqKey) {
		return o, fmt.Errorf("XHTTP session and sequence use the same key")
	}
	return o, nil
}

func endpointURL(host, path string) (url.URL, error) {
	if host != "" && !httpguts.ValidHostHeader(host) {
		return url.URL{}, fmt.Errorf("invalid XHTTP host %q", host)
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || strings.HasPrefix(path, "//") || strings.Contains(path, "#") {
		return url.URL{}, fmt.Errorf("invalid XHTTP path %q", path)
	}
	u.Path = normalizePath(u.Path)
	u.RawPath = ""
	u.Scheme = "https"
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u.Host = host
	return *u, nil
}

func (c *codec) request(ctx context.Context, opts Options, endpoint url.URL, method, id, seq string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, err
	}
	for k, vs := range opts.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	c.applyPaddingToRequest(req)
	c.applyMetaToRequest(req, id, seq)
	if body != nil && seq == "" && !opts.NoGRPCHeader {
		req.Header.Set("Content-Type", "application/grpc")
	}
	return req, nil
}

func validateMode(o Options) error {
	if o.Mode != ModePacketUp && (o.Method == http.MethodGet || o.UplinkDataPlacement == PlacementHeader || o.UplinkDataPlacement == PlacementCookie) {
		return fmt.Errorf("XHTTP uplink placement/method requires packet-up, got %s", o.Mode)
	}
	return nil
}
