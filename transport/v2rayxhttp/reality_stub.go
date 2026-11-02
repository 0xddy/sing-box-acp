//go:build !with_utls

package v2rayxhttp

import "github.com/sagernet/sing-box/common/tls"

func isReality(c tls.Config) bool { return false }
