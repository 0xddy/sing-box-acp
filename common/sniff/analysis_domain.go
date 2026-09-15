package sniff

import "slices"

// An ECH outer name identifies a cover/public endpoint, not the encrypted
// destination. Preserve the routing Domain, but do not present it as an
// identified visit in analytics. GREASE ECH is intentionally conservative too.
func analysisServerName(name string, extensions []uint16) string {
	const encryptedClientHelloExtension uint16 = 0xfe0d
	if slices.Contains(extensions, encryptedClientHelloExtension) {
		return ""
	}
	return name
}
