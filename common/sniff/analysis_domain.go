package sniff

import "slices"

// ECH and GREASE carry the same extension identifier. Report the observable
// flag without interpreting the visible server name or confirming ECH use.
func encryptedClientHelloPresent(extensions []uint16) bool {
	const encryptedClientHelloExtension uint16 = 0xfe0d
	return slices.Contains(extensions, encryptedClientHelloExtension)
}
