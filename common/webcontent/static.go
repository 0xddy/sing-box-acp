package webcontent

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
)

//go:embed assets/* templates/*
var resources embed.FS

type resource struct {
	data, compressed            []byte
	contentType, etag, gzipETag string
}

func newStatic(options option.WebOptions) (*Site, error) {
	tmpl, err := template.ParseFS(resources, "templates/page.html")
	if err != nil {
		return nil, err
	}
	files := make(map[string]resource)
	for _, route := range []string{"/", "/about"} {
		var page bytes.Buffer
		if err = tmpl.Execute(&page, struct {
			option.WebOptions
			About bool
		}{options, route == "/about"}); err != nil {
			return nil, err
		}
		files[route], err = makeResource(page.Bytes(), "text/html; charset=utf-8")
		if err != nil {
			return nil, err
		}
	}
	entries, err := resources.ReadDir("assets")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		data, readErr := resources.ReadFile("assets/" + entry.Name())
		if readErr != nil {
			return nil, readErr
		}
		files["/assets/"+entry.Name()], err = makeResource(data, mime.TypeByExtension(path.Ext(entry.Name())))
		if err != nil {
			return nil, err
		}
	}
	files["/favicon.svg"] = files["/assets/favicon.svg"]
	modifiedAt := time.Now().UTC().Truncate(time.Second)
	return &Site{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		file, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", file.contentType)
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("Vary", "Accept-Encoding")
		data, etag := file.data, file.etag
		if r.Header.Get("Range") == "" && acceptsGzip(r.Header.Get("Accept-Encoding")) {
			w.Header().Set("Content-Encoding", "gzip")
			data, etag = file.compressed, file.gzipETag
		}
		w.Header().Set("ETag", etag)
		// Assets are immutable for a configuration snapshot. ETag reflects the
		// actual content, including template configuration, rather than start time.
		http.ServeContent(w, r, r.URL.Path, modifiedAt, bytes.NewReader(data))
	})}, nil
}

func makeResource(data []byte, contentType string) (resource, error) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(data); err != nil {
		// Closing after a failed write only releases compression resources.
		_ = writer.Close()
		return resource{}, err
	}
	if err := writer.Close(); err != nil {
		return resource{}, err
	}
	encoded := compressed.Bytes()
	return resource{data, encoded, contentType, fmt.Sprintf(`"%x"`, sha256.Sum256(data)), fmt.Sprintf(`"%x"`, sha256.Sum256(encoded))}, nil
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
