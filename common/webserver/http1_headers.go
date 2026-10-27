package webserver

import (
	"bytes"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func parseHTTP1Headers(data []byte) (int, http.Header, error) {
	lines := strings.Split(string(data[:len(data)-4]), "\r\n")
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return 0, nil, fmt.Errorf("invalid website response status")
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, err
	}
	h := make(http.Header)
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return 0, nil, fmt.Errorf("invalid website response header")
		}
		h.Add(name, strings.TrimSpace(value))
	}
	return status, h, nil
}

func orderedHTTP1Headers(protocol string, status int, title string, h http.Header) []byte {
	var output bytes.Buffer
	fmt.Fprintf(&output, "%s %d %s\r\n", protocol, status, title)
	order := []string{"Date", "Server", "Upgrade", "Last-Modified", "ETag", "Accept-Ranges", "Allow", "Content-Length", "Vary", "Content-Range", "Keep-Alive", "Connection", "Transfer-Encoding", "Content-Type"}
	written := make(map[string]bool, len(order))
	for _, name := range order {
		key := http.CanonicalHeaderKey(name)
		for _, value := range h[key] {
			fmt.Fprintf(&output, "%s: %s\r\n", name, value)
		}
		written[key] = true
	}
	var rest []string
	for name := range h {
		if !written[name] {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		for _, value := range h[name] {
			fmt.Fprintf(&output, "%s: %s\r\n", name, value)
		}
	}
	output.WriteString("\r\n")
	return output.Bytes()
}
