// XHTTP configuration fields adapted from sing-xhttp v0.1.6 (MPL-2.0).
// See transport/v2rayxhttp/THIRD_PARTY_NOTICE.
package option

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// XHTTPRange accepts Xray-style numbers and "min-max" strings, or an explicit pair.
type XHTTPRange struct{ From, To int32 }

func (r *XHTTPRange) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty XHTTP range")
	}
	var values []int32
	switch data[0] {
	case '"':
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		for _, part := range strings.Split(s, "-") {
			v, err := strconv.ParseInt(part, 10, 32)
			if err != nil {
				return fmt.Errorf("invalid XHTTP range %q", s)
			}
			values = append(values, int32(v))
		}
	case '[':
		if err := json.Unmarshal(data, &values); err != nil {
			return err
		}
	default:
		var n int32
		if err := json.Unmarshal(data, &n); err != nil {
			return err
		}
		values = []int32{n}
	}
	if len(values) < 1 || len(values) > 2 || values[0] < 0 || values[len(values)-1] < values[0] {
		return fmt.Errorf("invalid XHTTP range: %s", data)
	}
	r.From, r.To = values[0], values[len(values)-1]
	return nil
}

func (r XHTTPRange) MarshalJSON() ([]byte, error) {
	if r.From == r.To {
		return json.Marshal(r.From)
	}
	return json.Marshal(fmt.Sprintf("%d-%d", r.From, r.To))
}

func (XHTTPRange) DescribeSchema(b schema.Builder) (*schema.Node, error) {
	return schema.AnyOf(schema.StringNode(), schema.IntegerNode(), &schema.Node{Type: "array", Items: schema.IntegerNode()}), nil
}

type V2RayXHTTPOptions struct {
	Mode    string               `json:"mode,omitempty" enum:"auto,packet-up,stream-up,stream-one"`
	Host    string               `json:"host,omitempty"`
	Path    string               `json:"path,omitempty"`
	Method  string               `json:"uplink_http_method,omitempty"`
	Headers badoption.HTTPHeader `json:"headers,omitempty"`

	NoGRPCHeader bool `json:"no_grpc_header,omitempty"`
	NoSSEHeader  bool `json:"no_sse_header,omitempty"`

	XPaddingBytes        *XHTTPRange `json:"x_padding_bytes,omitempty"`
	ScMaxEachPostBytes   *XHTTPRange `json:"sc_max_each_post_bytes,omitempty"`
	ScMaxBufferedPosts   int32       `json:"sc_max_buffered_posts,omitempty"`
	ScMinPostsIntervalMs *XHTTPRange `json:"sc_min_posts_interval_ms,omitempty"`
	ScStreamUpServerSecs *XHTTPRange `json:"sc_stream_up_server_secs,omitempty"`

	XPaddingObfsMode  bool   `json:"x_padding_obfs_mode,omitempty"`
	XPaddingPlacement string `json:"x_padding_placement,omitempty"`
	XPaddingKey       string `json:"x_padding_key,omitempty"`
	XPaddingHeader    string `json:"x_padding_header,omitempty"`
	XPaddingMethod    string `json:"x_padding_method,omitempty"`

	SessionPlacement string `json:"session_placement,omitempty"`
	SessionKey       string `json:"session_key,omitempty"`
	SeqPlacement     string `json:"seq_placement,omitempty"`
	SeqKey           string `json:"seq_key,omitempty"`

	UplinkDataPlacement string      `json:"uplink_data_placement,omitempty"`
	UplinkDataKey       string      `json:"uplink_data_key,omitempty"`
	UplinkChunkSize     *XHTTPRange `json:"uplink_chunk_size,omitempty"`

	SessionIDTable  string      `json:"session_table,omitempty"`
	SessionIDLength *XHTTPRange `json:"session_length,omitempty"`

	ServerMaxHeaderBytes int32 `json:"server_max_header_bytes,omitempty"`

	DownloadSettings *XHTTPDownloadOptions `json:"download_settings,omitempty"`

	Xmux *XHTTPMuxOptions `json:"xmux,omitempty"`
}

type XHTTPMuxOptions struct {
	MaxConcurrency   *XHTTPRange `json:"max_concurrency,omitempty"`
	MaxConnections   *XHTTPRange `json:"max_connections,omitempty"`
	CMaxReuseTimes   *XHTTPRange `json:"c_max_reuse_times,omitempty"`
	HMaxRequestTimes *XHTTPRange `json:"h_max_request_times,omitempty"`
	HMaxReusableSecs *XHTTPRange `json:"h_max_reusable_secs,omitempty"`
	HKeepAlivePeriod int32       `json:"h_keep_alive_period,omitempty"`
}

type XHTTPDownloadOptions struct {
	Host string `json:"host,omitempty"`
	Path string `json:"path,omitempty"`
}
