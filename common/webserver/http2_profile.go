package webserver

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/net/http2"
)

// Default-valued SETTINGS can be omitted without changing protocol semantics.
// Configure the engine to Apache's actual limits before using this serializer;
// never advertise a window or frame limit that differs from the engine's state.
type http2Profile struct {
	net.Conn
	prefix []byte
	ready  bool
}

func (c *http2Profile) Write(p []byte) (int, error) {
	if c.ready {
		return c.Conn.Write(p)
	}
	n := len(p)
	c.prefix = append(c.prefix, p...)
	if len(c.prefix) < 9 {
		return n, nil
	}
	size := int(c.prefix[0])<<16 | int(c.prefix[1])<<8 | int(c.prefix[2])
	if size > 1024 || size%6 != 0 || c.prefix[3] != byte(http2.FrameSettings) || c.prefix[4] != 0 || binary.BigEndian.Uint32(c.prefix[5:9]) != 0 {
		return 0, fmt.Errorf("unexpected website HTTP/2 initial frame")
	}
	if len(c.prefix) < 9+size {
		return n, nil
	}
	output := append([]byte(nil), c.prefix[:9]...)
	for offset := 9; offset < 9+size; offset += 6 {
		id := http2.SettingID(binary.BigEndian.Uint16(c.prefix[offset:]))
		value := binary.BigEndian.Uint32(c.prefix[offset+2:])
		if (id == http2.SettingMaxFrameSize && value == http2DefaultFrameSize) ||
			(id == http2.SettingHeaderTableSize && value == http2DefaultHeaderTableSize) ||
			(id == http2.SettingInitialWindowSize && value == http2DefaultWindowSize) ||
			id == http2.SettingMaxHeaderListSize {
			continue // Advisory header limit is enforced locally, as in Apache.
		}
		output = append(output, c.prefix[offset:offset+6]...)
	}
	length := len(output) - 9
	output[0], output[1], output[2] = byte(length>>16), byte(length>>8), byte(length)
	output = append(output, c.prefix[9+size:]...)
	c.ready, c.prefix = true, nil
	if err := writeProfileBytes(c.Conn, output); err != nil {
		return 0, err
	}
	return n, nil
}

func newHTTP2Server() *http2.Server {
	return &http2.Server{
		MaxConcurrentStreams: 100, MaxReadFrameSize: http2DefaultFrameSize,
		MaxDecoderHeaderTableSize: http2DefaultHeaderTableSize, MaxEncoderHeaderTableSize: http2DefaultHeaderTableSize,
		MaxUploadBufferPerStream: http2DefaultWindowSize, MaxUploadBufferPerConnection: (1 << 31) - 1,
		IdleTimeout: profileIdleTimeout, WriteByteTimeout: profileIOTimeout,
		NewWriteScheduler: func() http2.WriteScheduler { return http2.NewPriorityWriteScheduler(nil) },
	}
}

// These are RFC defaults, not arbitrary profile settings. A nondefault engine
// setting MUST remain on the wire even if the selected profile changes.
const (
	http2DefaultFrameSize       = 16384
	http2DefaultHeaderTableSize = 4096
	http2DefaultWindowSize      = 65535
)
