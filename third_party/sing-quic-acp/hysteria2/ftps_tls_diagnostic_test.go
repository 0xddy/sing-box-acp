//go:build ftps_diagnostic

package hysteria2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
)

// This control carries a real TLS data stream over HY2 and sing's relay. The
// target only sends TLS handshake records and its normal close_notify; it does
// not inject an artificial reverse reply while an upload is buffered. It is
// not a complete FTP control/data-session or OpenClash/v2rayN reproduction.
func TestDiagnosticHY2TLSUploadNormalClose(t *testing.T) {
	payload := bytes.Repeat([]byte("TLS upload payload"), 90000)
	wantHash := sha256.Sum256(payload)
	for _, fullClose := range []bool{false, true} {
		name := "tls_close_write_then_read"
		if fullClose {
			name = "tls_full_close"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), testIOTimeout)
			defer cancel()
			destination, remote := diagnosticTCPPair(t)
			serverConfig, clientConfig := testTLSConfigs(t)
			sinkResults := make(chan diagnosticTLSUploadResult, 1)
			relayResults := make(chan error, 1)
			go func() {
				server := tls.Server(remote, serverConfig.(*testTLSConfig).config.Clone())
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(testIOTimeout))
				if err := server.HandshakeContext(ctx); err != nil {
					sinkResults <- diagnosticTLSUploadResult{readErr: err}
					return
				}
				hash := sha256.New()
				n, readErr := io.Copy(hash, diagnosticTLSSlowReader{Reader: server})
				closeErr := server.CloseWrite()
				sinkResults <- diagnosticTLSUploadResult{
					received: n, hash: hash.Sum(nil), readErr: readErr, closeErr: closeErr,
				}
			}()
			handler := &diagnosticConnectionHandler{handle: func(conn net.Conn) {
				defer conn.Close()
				defer destination.Close()
				_ = destination.SetDeadline(time.Now().Add(testIOTimeout))
				if err := conn.(*serverConn).HandshakeSuccess(); err != nil {
					relayResults <- err
					return
				}
				relayResults <- bufio.CopyConn(ctx, conn, destination)
			}}
			env := startDiagnosticService(t, handler)
			transport := dialTestStream(t, env.newClient(t, "diagnostic-password"))
			client := tls.Client(transport, clientConfig.(*testTLSConfig).config.Clone())
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(testIOTimeout))
			if err := client.HandshakeContext(ctx); err != nil {
				t.Fatalf("TLS handshake: %v", err)
			}
			n, err := client.Write(payload)
			if err != nil || n != len(payload) {
				t.Fatalf("TLS Write = %d, %v; want %d, nil", n, err, len(payload))
			}
			if fullClose {
				err = client.Close()
			} else {
				err = client.CloseWrite()
			}
			if err != nil {
				t.Fatalf("close TLS upload: %v", err)
			}
			if !fullClose {
				response, err := io.ReadAll(client)
				if (err != nil && !errors.Is(err, io.EOF)) || len(response) != 0 {
					t.Fatalf("read TLS close_notify: received=%d, err=%v", len(response), err)
				}
				_ = client.Close()
			}
			var result diagnosticTLSUploadResult
			select {
			case result = <-sinkResults:
			case <-ctx.Done():
				t.Fatal("timed out waiting for TLS sink")
			}
			var relayErr error
			select {
			case relayErr = <-relayResults:
			case <-ctx.Done():
				t.Fatal("timed out waiting for relay")
			}
			t.Logf("TLS version=%#x, client Write=%d, server read=%d, SHA256 matches=%t, server read error=%v, server close_notify=%v, relay=%v",
				client.ConnectionState().Version, n, result.received, bytes.Equal(result.hash, wantHash[:]), result.readErr, result.closeErr, relayErr)
			if result.received != int64(len(payload)) || !bytes.Equal(result.hash, wantHash[:]) || result.readErr != nil {
				t.Fatalf("TLS upload did not complete intact: received=%d/%d, read error=%v", result.received, len(payload), result.readErr)
			}
		})
	}
}

type diagnosticTLSUploadResult struct {
	received int64
	hash     []byte
	readErr  error
	closeErr error
}

type diagnosticTLSSlowReader struct{ io.Reader }

func (r diagnosticTLSSlowReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		time.Sleep(time.Millisecond)
	}
	return n, err
}
