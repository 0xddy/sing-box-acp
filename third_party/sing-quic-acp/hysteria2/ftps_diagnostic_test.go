//go:build ftps_diagnostic

package hysteria2

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// This diagnostic uses real HY2/QUIC transport and sing's actual CopyConn.
// The paused read simulates upload backpressure while a delayed reverse reply
// arrives. It is not an FTPS or OpenClash/v2rayN end-to-end reproduction. The
// 65500-byte pause is deliberately selected, not a discovered transport limit.
func TestDiagnosticHY2UploadCloseWithDelayedReply(t *testing.T) {
	const pauseAfter = 65500
	payload := bytes.Repeat([]byte("upload-payload-"), 40000)
	for _, fullClose := range []bool{false, true} {
		name := "send_fin_and_keep_reading"
		if fullClose {
			name = "close_both_directions"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), testIOTimeout)
			defer cancel()
			destination, remote := diagnosticTCPPair(t)
			uploadWritten := make(chan struct{})
			results := make(chan diagnosticUploadResult, 1)
			handler := &diagnosticConnectionHandler{handle: func(conn net.Conn) {
				server := conn.(*serverConn)
				defer server.Close()
				if err := server.HandshakeSuccess(); err != nil {
					results <- diagnosticUploadResult{copyErr: err}
					return
				}
				if _, err := server.Write([]byte{1}); err != nil {
					results <- diagnosticUploadResult{copyErr: err}
					return
				}
				paused := &diagnosticPausedConn{
					Conn: conn, remaining: pauseAfter, release: make(chan struct{}),
					ctx: ctx, writeErr: make(chan error, 1),
				}
				defer destination.Close()
				defer remote.Close()
				_ = remote.SetDeadline(time.Now().Add(testIOTimeout))
				sinkResult := make(chan diagnosticUploadResult, 1)
				go func() {
					result := diagnosticUploadResult{}
					prefix := make([]byte, pauseAfter)
					n, err := io.ReadFull(remote, prefix)
					result.received = n
					if err != nil {
						result.sinkErr = err
						sinkResult <- result
						return
					}
					select {
					case <-uploadWritten:
					case <-ctx.Done():
						result.sinkErr = ctx.Err()
						sinkResult <- result
						return
					}
					if fullClose {
						select {
						case <-server.Stream.Context().Done():
							result.stopSending = context.Cause(server.Stream.Context())
						case <-ctx.Done():
							result.sinkErr = ctx.Err()
							sinkResult <- result
							return
						}
					}
					_, result.replyErr = remote.Write([]byte{2})
					if !fullClose {
						paused.unblock()
					}
					remainder, err := io.ReadAll(remote)
					result.received += len(remainder)
					result.sinkErr = err
					result.contentMatches = bytes.Equal(append(prefix, remainder...), payload[:result.received])
					_ = remote.Close()
					sinkResult <- result
				}()
				copyErr := bufio.CopyConn(ctx, paused, destination)
				result := <-sinkResult
				result.copyErr = copyErr
				select {
				case result.responseErr = <-paused.writeErr:
				default:
				}
				results <- result
			}}
			env := startDiagnosticService(t, handler)
			conn := dialTestStream(t, env.newClient(t, "diagnostic-password"))
			_ = conn.SetDeadline(time.Now().Add(testIOTimeout))
			if _, err := conn.Write(nil); err != nil {
				t.Fatal(err)
			}
			ready := make([]byte, 1)
			if _, err := io.ReadFull(conn, ready); err != nil {
				t.Fatalf("establish HY2 response before uploading: %v", err)
			}
			n, err := conn.Write(payload)
			if err != nil || n != len(payload) {
				t.Fatalf("upload Write = %d, %v; want %d, nil", n, err, len(payload))
			}
			if fullClose {
				err = conn.Close()
			} else {
				err = conn.(*clientConn).Stream.Close()
			}
			close(uploadWritten)
			if err != nil {
				t.Fatal(err)
			}
			if !fullClose {
				if _, err := io.ReadFull(conn, ready); err != nil {
					t.Fatalf("read delayed response: %v", err)
				}
			}
			var result diagnosticUploadResult
			select {
			case result = <-results:
			case <-ctx.Done():
				t.Fatal("timed out waiting for relay")
			}
			t.Logf("client Write=%d, sink received=%d, STOP_SENDING=%v, response Write=%v, CopyConn=%v", n, result.received, result.stopSending, result.responseErr, result.copyErr)
			if !result.contentMatches {
				t.Fatal("received bytes differ from source prefix")
			}
			if result.replyErr != nil || result.sinkErr != nil {
				t.Fatalf("unexpected sink error: reply=%v, read=%v", result.replyErr, result.sinkErr)
			}
			if !fullClose {
				if result.received != len(payload) || result.copyErr != nil {
					t.Fatalf("FIN-only control did not preserve upload: %+v", result)
				}
				return
			}
			var streamErr *quic.StreamError
			if !errors.As(result.stopSending, &streamErr) || !streamErr.Remote || streamErr.ErrorCode != 0 {
				t.Fatalf("expected remote STOP_SENDING(0), got %v", result.stopSending)
			}
			if result.responseErr == nil || result.received != pauseAfter {
				t.Fatalf("expected reverse write failure to interrupt buffered upload at pause: %+v", result)
			}
		})
	}
}

// The normal client Close cancels its response read as well as sending upload
// FIN. If dialing the target delayed the HY2 handshake response, that response
// fails even though a complete upload remains readable. The close-on-failure
// branch models the router's handshake-failure cleanup; preserve_read is the
// control proving that QUIC itself retained the upload before that cleanup.
func TestDiagnosticHY2UploadCloseBeforeHandshakeReply(t *testing.T) {
	payload := bytes.Repeat([]byte("upload-payload-"), 40000)
	for _, closeOnFailure := range []bool{false, true} {
		name := "preserve_upload_read_after_response_error"
		if closeOnFailure {
			name = "close_upload_read_after_response_error"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), testIOTimeout)
			defer cancel()
			results := make(chan diagnosticUploadResult, 1)
			handler := &diagnosticConnectionHandler{handle: func(conn net.Conn) {
				defer conn.Close()
				server := conn.(*serverConn)
				result := diagnosticUploadResult{}
				select {
				case <-server.Stream.Context().Done():
					result.stopSending = context.Cause(server.Stream.Context())
				case <-ctx.Done():
					result.sinkErr = ctx.Err()
					results <- result
					return
				}
				result.responseErr = server.HandshakeSuccess()
				if closeOnFailure && result.responseErr != nil {
					_ = conn.Close()
				}
				_ = conn.SetReadDeadline(time.Now().Add(testIOTimeout))
				received, err := io.ReadAll(conn)
				result.received, result.sinkErr = len(received), err
				result.contentMatches = bytes.Equal(received, payload[:len(received)])
				results <- result
			}}
			env := startDiagnosticService(t, handler)
			conn := dialTestStream(t, env.newClient(t, "diagnostic-password"))
			_ = conn.SetWriteDeadline(time.Now().Add(testIOTimeout))
			n, err := conn.Write(payload)
			if err != nil || n != len(payload) {
				t.Fatalf("upload Write = %d, %v; want %d, nil", n, err, len(payload))
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			var result diagnosticUploadResult
			select {
			case result = <-results:
			case <-ctx.Done():
				t.Fatal("timed out waiting for delayed handshake")
			}
			t.Logf("client Write=%d, server read=%d, STOP_SENDING=%v, HandshakeSuccess=%v, read error=%v", n, result.received, result.stopSending, result.responseErr, result.sinkErr)
			var streamErr *quic.StreamError
			if !errors.As(result.responseErr, &streamErr) || !streamErr.Remote || streamErr.ErrorCode != 0 {
				t.Fatalf("expected remote STOP_SENDING(0) on handshake response, got %v", result.responseErr)
			}
			want := len(payload)
			if closeOnFailure {
				want = 0
			}
			if result.received != want || !result.contentMatches {
				t.Fatalf("server read=%d with matching contents=%v; want %d", result.received, result.contentMatches, want)
			}
			if !closeOnFailure && result.sinkErr != nil && !errors.Is(result.sinkErr, io.EOF) {
				t.Fatalf("preserved upload ended with error: %v", result.sinkErr)
			}
		})
	}
}

type diagnosticUploadResult struct {
	received       int
	contentMatches bool
	stopSending    error
	responseErr    error
	copyErr        error
	sinkErr        error
	replyErr       error
}

type diagnosticPausedConn struct {
	net.Conn
	remaining int
	release   chan struct{}
	once      sync.Once
	ctx       context.Context
	writeErr  chan error
}

func (c *diagnosticPausedConn) Read(p []byte) (int, error) {
	if c.remaining > 0 {
		if len(p) > c.remaining {
			p = p[:c.remaining]
		}
		n, err := c.Conn.Read(p)
		c.remaining -= n
		return n, err
	}
	select {
	case <-c.release:
		return c.Conn.Read(p)
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}
}

func (c *diagnosticPausedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err != nil {
		select {
		case c.writeErr <- err:
		default:
		}
	}
	return n, err
}

func (c *diagnosticPausedConn) unblock() { c.once.Do(func() { close(c.release) }) }

func (c *diagnosticPausedConn) Close() error {
	err := c.Conn.Close()
	c.unblock()
	return err
}

type diagnosticConnectionHandler struct {
	testEchoHandler
	handle func(net.Conn)
}

func (h *diagnosticConnectionHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	go h.handle(conn)
}

func startDiagnosticService(t *testing.T, handler ServerHandler) *testServiceEnv {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service, err := NewService[testUserIdentity](ServiceOptions{
		Context: ctx, Logger: logger.NOP(), TLSConfig: serverTLS,
		UDPTimeout: 30 * time.Second, Handler: handler,
		SendBPS: 100 * 1024 * 1024, ReceiveBPS: 100 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	service.UpdateUsers([]testUserIdentity{{user: "diagnostic", generation: 1}}, []string{"diagnostic-password"})
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close(); _ = packetConn.Close() })
	if err := service.Start(packetConn); err != nil {
		t.Fatal(err)
	}
	return &testServiceEnv{service: service, address: M.SocksaddrFromNet(packetConn.LocalAddr()).Unwrap(), clientTLS: clientTLS, cancel: cancel}
}

func diagnosticTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}
