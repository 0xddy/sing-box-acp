package webserver

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/webprofile"
)

// http1Profile changes response presentation after net/http has performed its
// normal parsing and framing. http1RequestReader adapts the two textual version
// probes before parsing. Body bytes remain unchanged in both directions.
type http1Profile struct {
	net.Conn
	input     *http1RequestReader
	mu        sync.Mutex
	buffer    []byte
	phase     responsePhase
	remaining int64
	method    string
	expect    string
	handled   bool
	closing   bool
	keepAlive bool
	discard   bool
	requests  int
}

type responsePhase uint8

const (
	responseHeaders responsePhase = iota
	responseBody
	responseChunkSize
	responseChunkData
	responseTrailers
	responseOpaque
)

func newHTTP1Profile(conn net.Conn) *http1Profile {
	profile := &http1Profile{Conn: conn, phase: responseHeaders}
	profile.input = newHTTP1RequestReader(conn, profile.observe)
	return profile
}

func (c *http1Profile) Read(p []byte) (int, error) { return c.input.Read(p) }

func (c *http1Profile) observe(r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.method = r.Method
	c.expect = strings.Join(r.Header.Values("Expect"), ", ")
}

func (c *http1Profile) begin(r *http.Request) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.method, c.handled, c.closing = r.Method, true, r.Close
	c.keepAlive = false
	for _, token := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "keep-alive") {
			c.keepAlive = true
		}
	}
	c.requests++
	return c.requests >= maxHTTP1Requests
}

func (c *http1Profile) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	for len(p) > 0 && !c.discard {
		switch c.phase {
		case responseOpaque:
			if err := writeProfileBytes(c.Conn, p); err != nil {
				return 0, err
			}
			p = nil
		case responseBody, responseChunkData:
			size := min(int64(len(p)), c.remaining)
			if err := writeProfileBytes(c.Conn, p[:size]); err != nil {
				return 0, err
			}
			p, c.remaining = p[size:], c.remaining-size
			if c.remaining == 0 {
				if c.phase == responseChunkData {
					c.phase = responseChunkSize
				} else {
					c.finish()
				}
			}
		default:
			// Buffer only framing lines/headers, never the response payload.
			c.buffer = append(c.buffer, p[0])
			p = p[1:]
			if len(c.buffer) > 1<<20 {
				return 0, fmt.Errorf("website response header exceeds limit")
			}
			if c.phase == responseHeaders {
				if bytes.HasSuffix(c.buffer, []byte("\r\n\r\n")) {
					if err := c.headers(); err != nil {
						return 0, err
					}
					c.buffer = c.buffer[:0]
				}
			} else if bytes.HasSuffix(c.buffer, []byte("\r\n")) {
				line := c.buffer
				if c.phase == responseChunkSize {
					value, _, _ := strings.Cut(string(line[:len(line)-2]), ";")
					size, err := strconv.ParseUint(value, 16, 63)
					if err != nil || size > (1<<63)-3 {
						return 0, fmt.Errorf("invalid website response chunk size")
					}
					if size == 0 {
						c.phase = responseTrailers
					} else {
						c.phase, c.remaining = responseChunkData, int64(size)+2
					}
				} else if len(line) == 2 {
					c.finish()
				}
				if err := writeProfileBytes(c.Conn, line); err != nil {
					return 0, err
				}
				c.buffer = c.buffer[:0]
			}
		}
	}
	return n, nil
}

func (c *http1Profile) finish() {
	c.phase, c.method, c.handled, c.closing = responseHeaders, "", false, false
	c.keepAlive = false
	c.expect = ""
}

func (c *http1Profile) headers() error {
	status, h, err := parseHTTP1Headers(c.buffer)
	if err != nil {
		return err
	}
	if status == 100 {
		c.phase = responseHeaders
		return writeProfileBytes(c.Conn, c.buffer)
	}
	if status >= 400 && !c.handled {
		return c.writeParserError(status)
	}
	h.Set("Server", webprofile.Server)
	if status >= 200 && h.Get("Date") == "" {
		h.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}
	// Use the same charset spelling as AddDefaultCharset UTF-8.
	if value := h.Get("Content-Type"); strings.HasSuffix(value, "charset=utf-8") {
		h.Set("Content-Type", strings.TrimSuffix(value, "utf-8")+"UTF-8")
	}
	if err := c.beginResponseBody(status, h); err != nil {
		return err
	}
	title := http.StatusText(status)
	if status == http.StatusRequestURITooLong {
		title = "Request-URI Too Long"
	}
	return writeProfileBytes(c.Conn, orderedHTTP1Headers("HTTP/1.1", status, title, h))
}

func (c *http1Profile) writeParserError(status int) error {
	// These responses bypass Handler entirely in net/http. Their status
	// suffixes and plain-text bodies otherwise reveal the Go parser.
	if status == 431 || status == 501 {
		status = http.StatusBadRequest
	}
	detail := ""
	if status == http.StatusExpectationFailed {
		detail = webprofile.ExpectationDetail(c.expect)
	}
	title, body := webprofile.ErrorPage(status, c.method, detail)
	h := http.Header{"Date": {time.Now().UTC().Format(http.TimeFormat)}, "Server": {webprofile.Server},
		"Content-Length": {strconv.Itoa(len(body))}, "Connection": {"close"}, "Content-Type": {"text/html; charset=iso-8859-1"}}
	c.discard = true
	if c.method == http.MethodHead {
		h.Del("Content-Length")
		return writeProfileBytes(c.Conn, orderedHTTP1Headers("HTTP/1.1", status, title, h))
	}
	return writeProfileBytes(c.Conn, append(orderedHTTP1Headers("HTTP/1.1", status, title, h), body...))
}

func (c *http1Profile) beginResponseBody(status int, h http.Header) error {
	var err error
	if status == http.StatusSwitchingProtocols {
		c.phase = responseOpaque
		if c.input != nil {
			c.input.switchToOpaque() // Hijacked bytes are no longer HTTP requests.
		}
	} else if status < 200 {
		c.phase = responseHeaders
	} else {
		c.connectionHeaders(h)
		switch {
		case c.method == http.MethodHead || status == 204 || status == 304:
			c.finish()
		case strings.EqualFold(h.Get("Transfer-Encoding"), "chunked"):
			c.phase = responseChunkSize
		case h.Get("Content-Length") != "":
			c.remaining, err = strconv.ParseInt(h.Get("Content-Length"), 10, 64)
			if err != nil || c.remaining < 0 {
				return fmt.Errorf("invalid website response length")
			}
			c.phase = responseBody
			if c.remaining == 0 {
				c.finish()
			}
		default:
			c.phase = responseOpaque // close-delimited HTTP/1.0 response
		}
	}
	return nil
}

func (c *http1Profile) connectionHeaders(h http.Header) {
	closing := c.closing || strings.EqualFold(h.Get("Connection"), "close") || c.requests >= maxHTTP1Requests
	if closing {
		h.Del("Keep-Alive")
		h.Set("Connection", "close")
	} else if c.keepAlive {
		h.Set("Keep-Alive", fmt.Sprintf("timeout=%d, max=%d", int(profileIdleTimeout.Seconds()), maxHTTP1Requests-c.requests+1))
		h.Set("Connection", "Keep-Alive")
	} else {
		// HTTP/1.1 persistence is implicit. Apache sends Keep-Alive only
		// when the client explicitly asks for that connection token.
		h.Del("Keep-Alive")
		h.Del("Connection")
	}
}
