//go:build with_utls

package v2rayxhttp_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"

	"golang.org/x/net/proxy"
)

const testUUID = "ed7992df-2e51-4f69-a666-755e1613f795"

func TestVLESSReality(t *testing.T) {
	decoy := httptest.NewUnstartedServer(http.NotFoundHandler())
	decoy.EnableHTTP2 = true
	decoy.StartTLS()
	t.Cleanup(decoy.Close)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private := base64.RawURLEncoding.EncodeToString(key.Bytes())
	public := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(w, r.Body) }))
	t.Cleanup(target.Close)
	for _, tc := range []struct{ name, client, server string }{
		{"ACP", "acp", "acp"}, {"Xray_client", "xray", "acp"}, {"Xray_server", "acp", "xray"}, {"LX_client", "lx", "acp"},
	} {
		modes := []string{"auto", "packet-up", "stream-up", "stream-one", "packet-headers", "packet-cookies"}
		if tc.name == "ACP" {
			modes = append(modes, "raw-vision")
		}
		for _, mode := range modes {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				xray, lx := os.Getenv("XRAY_BIN"), os.Getenv("SING_BOX_LX_BIN")
				if (tc.client == "xray" || tc.server == "xray") && xray == "" {
					t.Skip("set XRAY_BIN to the official Xray executable")
				}
				if tc.client == "lx" && lx == "" {
					t.Skip("set SING_BOX_LX_BIN to a sing-box-lx executable built with with_xhttp and with_utls")
				}
				serverPort := freePort(t)
				flow := ""
				acpExtra, xrayExtra := "", ""
				transportMode := mode
				if mode == "packet-headers" || mode == "packet-cookies" {
					transportMode = "packet-up"
					placement := "header"
					if mode == "packet-cookies" {
						placement = "cookie"
					}
					acpExtra = fmt.Sprintf(`,"session_placement":"header","session_key":"X-Session","session_table":"hex","session_length":"16","seq_placement":"query","seq_key":"n","sc_max_each_post_bytes":"4096","sc_min_posts_interval_ms":"1","uplink_http_method":"GET","uplink_data_placement":%q,"uplink_chunk_size":"512-1024","x_padding_bytes":"85-95","x_padding_obfs_mode":true,"x_padding_placement":"header","x_padding_header":"X-Pad","x_padding_method":"tokenish","headers":{"X-Site":"acp"},"xmux":{"max_connections":2,"h_max_request_times":20}`, placement)
					xrayExtra = fmt.Sprintf(`,"sessionPlacement":"header","sessionKey":"X-Session","sessionIDTable":"hex","sessionIDLength":"16","seqPlacement":"query","seqKey":"n","scMaxEachPostBytes":"4096","scMinPostsIntervalMs":"1","uplinkHTTPMethod":"GET","uplinkDataPlacement":%q,"uplinkChunkSize":"512-1024","xPaddingBytes":"85-95","xPaddingObfsMode":true,"xPaddingPlacement":"header","xPaddingHeader":"X-Pad","xPaddingMethod":"tokenish","headers":{"X-Site":"acp"},"xmux":{"maxConnections":2,"hMaxRequestTimes":20}`, placement)
				}
				transport := fmt.Sprintf(`,"transport":{"type":"xhttp","mode":%q,"path":"/acp-test","host":"example.com"%s}`, transportMode, acpExtra)
				xrayOpts := fmt.Sprintf(`{"path":"/acp-test","host":"example.com","mode":%q%s}`, transportMode, xrayExtra)
				if mode == "raw-vision" {
					flow = "xtls-rprx-vision"
					transport = ""
				}
				var acpServer *box.Box
				if tc.server == "acp" {
					t.Cleanup(func() {
						l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", serverPort))
						if err != nil {
							t.Error("rebind inbound after close:", err)
						} else {
							l.Close()
						}
					})
					cfg := fmt.Sprintf(`{"inbounds":[{"type":"vless","tag":"in","listen":"127.0.0.1","listen_port":%d,"users":[{"name":"test","uuid":%q,"flow":%q}],"tls":{"enabled":true,"server_name":"example.com","reality":{"enabled":true,"handshake":{"server":"127.0.0.1","server_port":%d},"private_key":%q,"short_id":["aabb"]}}%s}],"outbounds":[{"type":"direct","tag":"direct"}]}`, serverPort, testUUID, flow, decoy.Listener.Addr().(*net.TCPAddr).Port, private, transport)
					acpServer = startACP(t, cfg)
				} else {
					cfg := fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none","clients":[{"id":%q}]},"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"target":%q,"serverNames":["example.com"],"privateKey":%q,"shortIds":["aabb"]},"xhttpSettings":%s}}],"outbounds":[{"protocol":"freedom"}]}`, serverPort, testUUID, decoy.Listener.Addr().String(), private, xrayOpts)
					startPeer(t, xray, cfg, serverPort, true)
				}
				socksPort := freePort(t)
				if tc.client == "xray" {
					cfg := fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":%q,"encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"serverName":"example.com","fingerprint":"chrome","publicKey":%q,"shortId":"aabb"},"xhttpSettings":%s}}]}`, socksPort, serverPort, testUUID, public, xrayOpts)
					startPeer(t, xray, cfg, socksPort, true)
				} else {
					cfg := fmt.Sprintf(`{"inbounds":[{"type":"socks","tag":"local","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"vless","tag":"proxy","server":"127.0.0.1","server_port":%d,"uuid":%q,"flow":%q,"tls":{"enabled":true,"server_name":"example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":%q,"short_id":"aabb"}}%s}]}`, socksPort, serverPort, testUUID, flow, public, transport)
					if tc.client == "acp" {
						startACP(t, cfg)
					} else {
						startPeer(t, lx, cfg, socksPort, false)
					}
				}
				socks, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				tr := &http.Transport{DialContext: socks.(proxy.ContextDialer).DialContext}
				defer tr.CloseIdleConnections()
				client := http.Client{Transport: tr, Timeout: 10 * time.Second}
				payload := bytes.Repeat([]byte("VLESS over REALITY\x00"), 65536)
				resp, err := client.Post(target.URL, "application/octet-stream", bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				echoed, err := io.ReadAll(resp.Body)
				if err != nil || resp.StatusCode != 200 || !bytes.Equal(echoed, payload) {
					t.Fatalf("echo: HTTP %d, received %d of %d bytes, err=%v", resp.StatusCode, len(echoed), len(payload), err)
				}
				if tc.client == "acp" && acpServer != nil && mode == "stream-one" {
					verifyUserUpdates(t, acpServer, socks.(proxy.ContextDialer))
				}

			})
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startACP(t *testing.T, cfg string) *box.Box {
	t.Helper()
	ctx := include.Context(context.Background())
	opts, err := singjson.UnmarshalExtendedContext[option.Options](ctx, []byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := instance.Close(); err != nil {
			t.Error(err)
		}
	})
	return instance
}

func startPeer(t *testing.T, bin, cfg string, port int, xray bool) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if xray {
		cfg = strings.Replace(cfg, "{", `{"log":{"loglevel":"info"},`, 1)
	}
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "-c", path}
	if xray {
		args = []string{"run", "-config", path}
	}
	cmd := exec.Command(bin, args...)
	log, err := os.Create(filepath.Join(dir, "peer.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Log(string(b))
		}
	})
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("peer did not start listening on %s", address)
}

// User updates act on VLESS authentication, above the XHTTP transport. Verify
// the old stream survives adding a user and stale credentials cannot reconnect.
func verifyUserUpdates(t *testing.T, b *box.Box, dialer proxy.ContextDialer) {
	t.Helper()
	in, ok := b.Inbound().Get("in")
	if !ok {
		t.Fatal("missing VLESS inbound")
	}
	update := in.(interface {
		UpdateUsers([]option.VLESSUser) error
	}).UpdateUsers
	peer, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	go func() {
		for {
			c, err := peer.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	dial := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return dialer.DialContext(ctx, "tcp", peer.Addr().String())
	}
	echo := func(c net.Conn) error {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		var buf [4]byte
		if _, err := io.ReadFull(c, buf[:]); err != nil {
			return err
		}
		if string(buf[:]) != "ping" {
			return fmt.Errorf("unexpected echo %q", buf)
		}
		return nil
	}
	live, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if err := echo(live); err != nil {
		t.Fatal(err)
	}
	user := option.VLESSUser{Name: "test", UUID: testUUID}
	other := option.VLESSUser{Name: "second", UUID: "8c4ba3ac-eeca-4c96-9022-efbe54cfddc5"}
	if err := update([]option.VLESSUser{user, other}); err != nil {
		t.Fatal(err)
	}
	invalid := other
	invalid.Flow = "xtls-rprx-vision"
	if err := update([]option.VLESSUser{invalid}); err == nil || !strings.Contains(err.Error(), "empty user flow") {
		t.Fatalf("unexpected hot update result: %v", err)
	}
	if err := echo(live); err != nil {
		t.Fatal("existing stream after update:", err)
	}
	authorized, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	err = echo(authorized)
	authorized.Close()
	if err != nil {
		t.Fatal("auth snapshot lost after rejected update:", err)
	}
	if err := update([]option.VLESSUser{other}); err != nil {
		t.Fatal(err)
	}
	stale, err := dial()
	if err == nil {
		defer stale.Close()
		if err := echo(stale); err == nil {
			t.Fatal("removed user opened a new stream")
		}
	}
}
