package naive_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Set ACP_NAIVE_BINARY to a pinned official Linux client. No production
// certificates, external destinations, system trust changes, or bypass flags.
func TestOfficialNaiveClient(t *testing.T) {
	binary := os.Getenv("ACP_NAIVE_BINARY")
	if binary == "" {
		t.Skip("set ACP_NAIVE_BINARY for official client interoperability")
	}
	version, err := exec.Command(binary, "--version").CombinedOutput()
	if err != nil {
		t.Fatal("client version:", err)
	}
	t.Log(strings.TrimSpace(string(version)))
	for _, protocol := range []string{"https", "quic"} {
		t.Run(protocol, func(t *testing.T) {
			_, address, cfg, _ := fixture(t)
			verified, err := tls.Dial("tcp", address, cfg)
			if err != nil {
				t.Fatal(err)
			}
			cert := verified.ConnectionState().PeerCertificates[0]
			_ = verified.Close()
			directory := t.TempDir()
			certPath := filepath.Join(directory, "trusted.pem")
			if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			probe, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			clientAddress := probe.Addr().String()
			_ = probe.Close()
			_, port, _ := net.SplitHostPort(address)
			config, err := json.Marshal(map[string]string{
				"listen":              "http://" + clientAddress,
				"proxy":               protocol + "://a:one@example.com:" + port,
				"host-resolver-rules": "MAP example.com 127.0.0.1",
			})
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(directory, "config.json")
			if err = os.WriteFile(configPath, config, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, configPath)
			command.Env = append(os.Environ(), "SSL_CERT_FILE="+certPath, "SSL_CERT_DIR="+directory)
			if err = command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = command.Wait() }()
			var conn net.Conn
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				conn, err = net.DialTimeout("tcp", clientAddress, 100*time.Millisecond)
				if err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				t.Fatal("client listener:", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
			_, err = fmt.Fprint(conn, "CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n")
			if err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != 200 {
				t.Fatalf("client CONNECT status %d", response.StatusCode)
			}
			for i := 0; i < 12; i++ {
				message := strings.Repeat(fmt.Sprintf("frame-%d", i), 4096)
				if _, err = io.WriteString(conn, message); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(message))
				if _, err = io.ReadFull(reader, got); err != nil {
					t.Fatal(err)
				}
				if string(got) != message {
					t.Fatal("client payload mismatch")
				}
			}
		})
	}
}
