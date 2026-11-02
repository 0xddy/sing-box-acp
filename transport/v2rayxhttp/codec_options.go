// Wire codec adapted from github.com/justinwoo280/sing-xhttp v0.1.6 (MPL-2.0).
// See THIRD_PARTY_NOTICE and LICENSE-MPL-2.0.
package v2rayxhttp

import (
	"math/rand/v2"

	"github.com/sagernet/sing-box/option"
)

type Range = option.XHTTPRange
type Options = option.V2RayXHTTPOptions

func orRange(r *Range, def Range) Range {
	if r == nil {
		return def
	}
	return *r
}

func rangeRand(r Range) int32 {
	if r.From == r.To {
		return r.To
	}
	return int32(int64(r.From) + rand.Int64N(int64(r.To)-int64(r.From)+1))
}

// Mode constants.
const (
	ModePacketUp  = "packet-up"
	ModeStreamUp  = "stream-up"
	ModeStreamOne = "stream-one"
	ModeAuto      = "auto"
)

// Placement constants for sessionId / seq / x_padding / uplink data.
//
// Not all placements are valid for every field:
//   - sessionId / seq: path, query, header, cookie
//   - x_padding (obfsMode=true):   query, header, cookie
//   - x_padding (obfsMode=false):  always query-in-header (Referer / x_padding) — default mode
//   - uplink data: body, header, cookie, auto
const (
	PlacementPath          = "path"
	PlacementQuery         = "query"
	PlacementHeader        = "header"
	PlacementCookie        = "cookie"
	PlacementQueryInHeader = "query-in-header"
	PlacementBody          = "body"
	PlacementAuto          = "auto"
)

// Predefined character sets for custom session ID generation.
var PredefinedTable = map[string]string{
	"ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"BASE36":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"Base62":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	"HEX":      "0123456789ABCDEF",
	"alphabet": "abcdefghijklmnopqrstuvwxyz",
	"base36":   "0123456789abcdefghijklmnopqrstuvwxyz",
	"hex":      "0123456789abcdef",
	"number":   "0123456789",
}

// Padding method constants.
const (
	PaddingMethodRepeatX  = "repeat-x"
	PaddingMethodTokenish = "tokenish"
)

// defaultUplinkChunkSize returns the chunk size for header/cookie payload
// placement when UplinkChunkSize is not explicitly configured.
func defaultUplinkChunkSize(placement string, scMaxEachPost Range) Range {
	switch placement {
	case PlacementCookie:
		return Range{From: 2 * 1024, To: 3 * 1024}
	case PlacementHeader:
		return Range{From: 3 * 1000, To: 4 * 1000}
	default:
		return scMaxEachPost
	}
}
