package webserver

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

// http1RequestReader adapts only complete request headers. The same net/http
// parser used by the server determines body framing; body and trailer bytes are
// always forwarded unchanged. Invalid framing disables adaptation and leaves
// rejection to net/http. HTTP/2 connections never use this reader.
type http1RequestReader struct {
	reader    *bufio.Reader
	observe   func(*http.Request)
	phase     requestPhase
	header    []byte
	sent      int // The server's one-byte background read may precede header parsing.
	pending   []byte
	remaining int64
	chunkEnd  [2]byte
	opaque    atomic.Bool
}

type requestPhase uint8

const (
	requestHeaders requestPhase = iota
	requestBody
	requestChunkSize
	requestChunkData
	requestTrailers
	requestOpaque
)

// Called by the response side when a successful upgrade leaves HTTP framing.
func (r *http1RequestReader) switchToOpaque() { r.opaque.Store(true) }

func newHTTP1RequestReader(reader io.Reader, observe func(*http.Request)) *http1RequestReader {
	return &http1RequestReader{reader: bufio.NewReader(reader), observe: observe, phase: requestHeaders}
}

func (r *http1RequestReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.pending) == 0 {
		if r.opaque.Load() {
			r.phase = requestOpaque
		}
		switch r.phase {
		case requestOpaque:
			return r.reader.Read(p)
		case requestHeaders:
			// net/http reads one byte in the background to detect disconnects.
			// Do not wait for a complete header there: its read is cancellable
			// when the previous response finishes, including with pipelining.
			if len(p) == 1 && len(r.header) == 0 {
				value, err := r.reader.ReadByte()
				if err != nil {
					return 0, err
				}
				r.header, r.sent, p[0] = append(r.header, value), 1, value
				return 1, nil
			}
			if err := r.readHeader(); err != nil {
				return 0, err
			}
		case requestBody, requestChunkData:
			n, err := r.reader.Read(p[:min(int64(len(p)), r.remaining)])
			if r.phase == requestChunkData {
				for i := max(int64(0), r.remaining-2); i < int64(n); i++ {
					r.chunkEnd[2-r.remaining+i] = p[i]
				}
			}
			r.remaining -= int64(n)
			if r.remaining == 0 {
				if r.phase == requestBody {
					r.phase = requestHeaders
				} else if r.chunkEnd == [2]byte{'\r', '\n'} {
					r.phase = requestChunkSize
				} else {
					r.phase = requestOpaque
				}
			}
			return n, err
		case requestChunkSize, requestTrailers:
			line, err := r.reader.ReadSlice('\n')
			if len(line) == 0 {
				return 0, err
			}
			r.pending = append(r.pending, line...)
			if err != nil || !bytes.HasSuffix(line, []byte("\r\n")) {
				r.phase = requestOpaque
			} else if r.phase == requestTrailers {
				if len(line) == 2 {
					r.phase = requestHeaders
				}
			} else {
				value, _, _ := strings.Cut(string(line[:len(line)-2]), ";")
				size, parseErr := strconv.ParseUint(value, 16, 63)
				if parseErr != nil || size > (1<<63)-3 {
					r.phase = requestOpaque
				} else if size == 0 {
					r.phase = requestTrailers
				} else {
					r.phase, r.remaining = requestChunkData, int64(size)+2
				}
			}
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *http1RequestReader) readHeader() error {
	const maxHeaderBytes = maxRequestHeaderBytes + 4096 // Match net/http's limit and read allowance.
	for {
		line, err := r.reader.ReadSlice('\n')
		r.header = append(r.header, line...)
		if len(r.header) > maxHeaderBytes || (err != nil && err != bufio.ErrBufferFull) {
			// Preserve every byte on partial reads/errors; never reinterpret an
			// incomplete or oversized request as an independently valid request.
			r.phase = requestOpaque
			r.pending, r.header = r.header[r.sent:], nil
			r.sent = 0
			if len(r.pending) > 0 {
				return nil
			}
			return err
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if bytes.HasSuffix(r.header, []byte("\n\r\n")) || bytes.HasSuffix(r.header, []byte("\n\n")) {
			break
		}
	}
	input := r.header
	if end := bytes.Index(input, []byte("\r\n")); end >= 0 {
		line := string(input[:end])
		if index := strings.LastIndexByte(line, ' '); index > 0 && !strings.HasPrefix(line, "PRI ") {
			if version := line[index+1:]; version == "HTTP/2.0" || version == "HTTP/3.0" {
				// Apache handles these textual version probes as HTTP/1 requests.
				// Normalize only the version token, never CL/TE, Host or syntax.
				input = bytes.Clone(input)
				copy(input[index+1:], "HTTP/1.1")
			}
		}
	}
	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(input)))
	if err != nil {
		r.phase = requestOpaque
		input = r.header // Failed validation must retain the original request.
	} else {
		// This reader contains headers only; closing a declared body may report
		// EOF. Body bytes are owned by the real server parser, not this preview.
		_ = request.Body.Close()
		r.observe(request)
		switch {
		case len(request.TransferEncoding) == 1 && request.TransferEncoding[0] == "chunked":
			r.phase = requestChunkSize
		case request.ContentLength > 0:
			r.phase, r.remaining = requestBody, request.ContentLength
		default:
			r.phase = requestHeaders
		}
	}
	r.pending, r.header = input[r.sent:], nil
	r.sent = 0
	return nil
}
