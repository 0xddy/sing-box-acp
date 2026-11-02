package juicity

import (
	"context"
	"errors"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	cubic "github.com/sagernet/sing-quic/congestion_meta1"
	bbr "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common/ntp"
)

const defaultAuthTimeout = 10 * time.Second
const defaultUDPTimeout = 5 * time.Minute
const streamsPerConnection = 30

func quicConfig(options qtls.QUICOptions, timeout time.Duration) *quic.Config {
	cfg := &quic.Config{HandshakeIdleTimeout: timeout}
	qtls.ApplyQUICOptions(cfg, options)
	return cfg
}

func validCongestion(name string) error {
	switch name {
	case "", "bbr", "cubic", "new_reno":
		return nil
	default:
		return errors.New("unknown Juicity congestion control: " + name)
	}
}

func setCongestion(ctx context.Context, c *quic.Conn, name string) {
	size := c.InitialPacketSize()
	if name == "" || name == "bbr" {
		c.SetCongestionControl(bbr.NewBbrSenderWithProfile(size, bbr.ProfileStandard))
		return
	}
	clock := ntp.TimeFuncFromContext(ctx)
	if clock == nil {
		clock = time.Now
	}
	c.SetCongestionControl(cubic.NewCubicSender(cubic.DefaultClock{TimeFunc: clock}, size, name == "new_reno"))
}
