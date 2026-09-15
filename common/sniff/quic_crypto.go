package sniff

import (
	"bytes"
	"context"
	"os"
	"sort"
)

const (
	maxQUICCryptoBytes     = 16 * 1024
	maxQUICCryptoFragments = 64
)

// Reassemble a bounded contiguous prefix. Gaps remain pending, retransmits must
// agree, and each iteration advances or exits (including zero-length frames).
func assembleQUICCrypto(ctx context.Context, fragments []qCryptoFragment) ([]byte, error) {
	if len(fragments) > maxQUICCryptoFragments {
		return nil, os.ErrInvalid
	}
	size := uint64(0)
	for _, fragment := range fragments {
		if fragment.length == 0 || fragment.length != uint64(len(fragment.payload)) || fragment.offset > maxQUICCryptoBytes || fragment.length > maxQUICCryptoBytes-fragment.offset || fragment.length > maxQUICCryptoBytes-size {
			return nil, os.ErrInvalid
		}
		size += fragment.length
	}
	sort.Slice(fragments, func(i, j int) bool { return fragments[i].offset < fragments[j].offset })
	data := make([]byte, 0, int(size))
	for _, fragment := range fragments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if fragment.offset > uint64(len(data)) {
			break
		}
		overlap := len(data) - int(fragment.offset)
		if overlap > len(fragment.payload) {
			overlap = len(fragment.payload)
		}
		if !bytes.Equal(data[int(fragment.offset):int(fragment.offset)+overlap], fragment.payload[:overlap]) {
			return nil, os.ErrInvalid
		}
		data = append(data, fragment.payload[overlap:]...)
	}
	return data, nil
}
