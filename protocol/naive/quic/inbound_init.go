package quic

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-quic"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/ntp"
)

func init() {
	naive.ConfigureHTTP3ListenerFunc = func(ctx context.Context, logger logger.Logger, listener *listener.Listener, handler http.Handler, tlsConfig tls.ServerConfig, options option.NaiveInboundOptions) (io.Closer, error) {
		err := qtls.ConfigureHTTP3(tlsConfig)
		if err != nil {
			return nil, err
		}
		if !common.Contains(tlsConfig.NextProtos(), http3.NextProtoH3) {
			tlsConfig.SetNextProtos(append(append([]string{}, tlsConfig.NextProtos()...), http3.NextProtoH3))
		}

		udpConn, err := listener.ListenUDP()
		if err != nil {
			return nil, err
		}

		var congestionControl func(conn *quic.Conn) congestion.CongestionControl
		timeFunc := ntp.TimeFuncFromContext(ctx)
		if timeFunc == nil {
			timeFunc = time.Now
		}
		switch options.QUICCongestionControl {
		case "", "bbr":
			congestionControl = func(conn *quic.Conn) congestion.CongestionControl {
				return congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestion_meta2.ProfileStandard)
			}
		case "cubic":
			congestionControl = func(conn *quic.Conn) congestion.CongestionControl {
				return congestion_meta1.NewCubicSender(
					congestion_meta1.DefaultClock{TimeFunc: timeFunc},
					conn.InitialPacketSize(),
					false,
				)
			}
		case "reno":
			congestionControl = func(conn *quic.Conn) congestion.CongestionControl {
				return congestion_meta1.NewCubicSender(
					congestion_meta1.DefaultClock{TimeFunc: timeFunc},
					conn.InitialPacketSize(),
					true,
				)
			}
		default:
			udpConn.Close()
			return nil, E.New("unknown quic congestion control: ", options.QUICCongestionControl)
		}

		quicListener, err := qtls.ListenEarly(udpConn, tlsConfig, &quic.Config{
			MaxIncomingStreams: naive.MaxConcurrentStreams,
			MaxIdleTimeout:     2 * time.Minute,
			KeepAlivePeriod:    15 * time.Second,
			Allow0RTT:          false,
			DisablePathManager: true,
		})
		if err != nil {
			udpConn.Close()
			return nil, err
		}

		h3Server := &http3.Server{
			Handler:     handler,
			IdleTimeout: 5 * time.Second,
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				if owner, ok := handler.(interface{ AcquireTransport() (func(), bool) }); ok {
					release, admitted := owner.AcquireTransport()
					if !admitted {
						_ = conn.CloseWithError(0, "")
					} else {
						context.AfterFunc(conn.Context(), release)
					}
				}
				conn.SetCongestionControl(congestionControl(conn))
				return log.ContextWithNewID(ctx)
			},
		}

		server := &ownedServer{server: h3Server, listener: quicListener, packet: udpConn, done: make(chan struct{})}
		go func() {
			defer close(server.done)
			defer udpConn.Close()
			defer quicListener.Close()
			defer func() {
				if value := recover(); value != nil {
					if reporter, ok := handler.(interface{ ReportRuntimeError(error) }); ok {
						reporter.ReportRuntimeError(fmt.Errorf("HTTP/3 panic: %v", value))
					}
				}
			}()
			sErr := h3Server.ServeListener(quicListener)
			if sErr != nil && !E.IsClosedOrCanceled(sErr) {
				if reporter, ok := handler.(interface{ ReportRuntimeError(error) }); ok {
					reporter.ReportRuntimeError(sErr)
				}
				logger.Error("http3 server closed: ", sErr)
			}
		}()

		return server, nil
	}
	naive.WrapError = qtls.WrapError
}

type ownedServer struct {
	server   *http3.Server
	listener io.Closer
	packet   net.PacketConn
	done     chan struct{}
	once     sync.Once
}

func (s *ownedServer) Close() error {
	s.once.Do(func() {
		_ = s.server.Close()
		_ = s.listener.Close()
		_ = s.packet.Close()
		<-s.done
	})
	return nil
}
