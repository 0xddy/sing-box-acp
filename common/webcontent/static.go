package webcontent

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/sagernet/sing-box/common/webprofile"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
)

type resource struct {
	data, compressed            []byte
	contentType, etag, gzipETag string
}

func newStatic(options option.WebOptions) (*Site, error) {
	modifiedAt := time.Now().UTC()
	file, err := makeResource([]byte(options.Content), "text/html; charset=UTF-8", modifiedAt)
	if err != nil {
		return nil, err
	}
	return &Site{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", webprofile.Server)
		if r.Method == http.MethodOptions {
			if r.URL.Path != "*" {
				w.Header().Set("Allow", staticAllow)
				w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			}
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
			w.Header().Set("Allow", staticAllow)
			if r.Method == http.MethodTrace {
				w.Header().Set("Allow", "")
			}
			if !knownMethod(r.Method) {
				apacheError(w, r, http.StatusNotImplemented)
				return
			}
			apacheError(w, r, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", file.contentType)
		data, etag := file.data, file.etag
		// mod_deflate skips known bodies no larger than its 68-byte overhead.
		if len(data) > 68 {
			w.Header().Set("Vary", "Accept-Encoding")
			if r.Header.Get("Range") == "" && acceptsGzip(r.Header.Get("Accept-Encoding")) {
				w.Header().Set("Content-Encoding", "gzip")
				data, etag = file.compressed, file.gzipETag
			}
		}
		w.Header().Set("ETag", etag)
		if value := r.Header.Get("Range"); value != "" && !validByteRanges(value) {
			// Apache ignores syntactically invalid ranges, reserving 416 for
			// valid ranges that do not overlap the selected representation.
			r = r.Clone(r.Context())
			r.Header.Del("Range")
		}
		http.ServeContent(&contentResponseWriter{ResponseWriter: w, request: r}, r, r.URL.Path, modifiedAt, bytes.NewReader(data))
	})}, nil
}

func validByteRanges(value string) bool {
	if !strings.HasPrefix(value, "bytes=") {
		return false
	}
	for _, item := range strings.Split(strings.TrimPrefix(value, "bytes="), ",") {
		start, end, ok := strings.Cut(strings.TrimSpace(item), "-")
		if !ok || (start == "" && end == "") {
			return false
		}
		var first, last uint64
		var err error
		if start != "" {
			first, err = strconv.ParseUint(start, 10, 63)
			if err != nil {
				return false
			}
		}
		if end != "" {
			last, err = strconv.ParseUint(end, 10, 63)
			if err != nil || (start != "" && last < first) {
				return false
			}
		}
	}
	return true
}

func makeResource(data []byte, contentType string, modifiedAt time.Time) (resource, error) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	// mod_deflate emits a zero timestamp and Unix OS byte in its gzip header.
	writer.Header.OS = 3
	if _, err := writer.Write(data); err != nil {
		// Closing after a failed write only releases compression resources.
		_ = writer.Close()
		return resource{}, err
	}
	if err := writer.Close(); err != nil {
		return resource{}, err
	}
	encoded := compressed.Bytes()
	// FileETag MTime Size serializes size followed by APR's microsecond mtime.
	// The virtual file is replaced whenever this website configuration changes.
	etag := fmt.Sprintf("%x-%x", len(data), modifiedAt.UnixMicro())
	return resource{data, encoded, contentType, `"` + etag + `"`, `"` + etag + `-gzip"`}, nil
}

func acceptsGzip(value string) bool {
	quality, wildcard := -1.0, 0.0
	for _, item := range strings.Split(value, ",") {
		parts := strings.Split(strings.TrimSpace(item), ";")
		q := 1.0
		for _, param := range parts[1:] {
			if key, raw, ok := strings.Cut(strings.TrimSpace(param), "="); ok && key == "q" {
				parsed, err := strconv.ParseFloat(raw, 64)
				if err != nil || parsed < 0 || parsed > 1 {
					q = 0
				} else {
					q = parsed
				}
			}
		}
		if strings.EqualFold(parts[0], "gzip") {
			quality = q
		}
		if parts[0] == "*" {
			wildcard = q
		}
	}
	if quality >= 0 {
		return quality > 0
	}
	return wildcard > 0
}
