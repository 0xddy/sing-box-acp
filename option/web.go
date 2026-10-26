package option

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// WebOptions contains only serializable website configuration. It is shared
// with the panel's configuration-only support module, never the HTTP runtime.
type WebOptions struct {
	Type        string `json:"type"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Body        string `json:"body,omitempty"`
	URL         string `json:"url,omitempty"`
}

func (o WebOptions) Validate() error {
	switch o.Type {
	case "static":
		if strings.TrimSpace(o.Title) == "" || len(o.Title) > 256 || len(o.Description) > 2048 || len(o.Body) > 65536 {
			return fmt.Errorf("static website requires a title (at most 256 bytes), description at most 2048 bytes and body at most 65536 bytes")
		}
		if o.URL != "" {
			return fmt.Errorf("static website does not accept url")
		}
	case "proxy":
		u, err := url.Parse(o.URL)
		if err != nil || u.Hostname() == "" || u.User != nil || strings.Contains(o.URL, "#") || u.RawQuery != "" || u.ForceQuery || strings.HasSuffix(u.Host, ":") || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("website url must be an HTTP(S) URL without credentials, query or fragment")
		}
		if u.Port() != "" {
			port, err := strconv.Atoi(u.Port())
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("website URL port must be between 1 and 65535")
			}
		}
		if o.Title != "" || o.Description != "" || o.Body != "" {
			return fmt.Errorf("proxy website does not accept static content")
		}
	default:
		return fmt.Errorf("unsupported website type %q", o.Type)
	}
	return nil
}
