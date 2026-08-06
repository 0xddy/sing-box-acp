package hysteria2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

const (
	testIOTimeout   = 5 * time.Second
	testIdleTimeout = 2 * time.Second
)

var testEchoDestination = M.ParseSocksaddr("192.0.2.10:5353")

// TestServiceRevocationOverRealQUICSessions drives the Hysteria2 service with
// real QUIC clients instead of fake sessions: rotating one user's credential
// must tear down that user's transport session, its TCP stream and its UDP
// association, must leave the other user untouched, and the rotated user must
// be able to reconnect immediately with the replacement credential.
func TestServiceRevocationOverRealQUICSessions(t *testing.T) {
	env := startTestService(t, []testUserIdentity{
		{user: "user-a", generation: 1},
		{user: "user-b", generation: 1},
	}, []string{"password-a-v1", "password-b"})

	clientA := env.newClient(t, "password-a-v1")
	clientB := env.newClient(t, "password-b")

	streamA := dialTestStream(t, clientA)
	streamB := dialTestStream(t, clientB)
	assertStreamEchoes(t, streamA, "a-before-rotation")
	assertStreamEchoes(t, streamB, "b-before-rotation")

	packetA := listenTestPacketConn(t, clientA)
	packetB := listenTestPacketConn(t, clientB)
	assertPacketEchoes(t, packetA, "a-udp-before-rotation")
	assertPacketEchoes(t, packetB, "b-udp-before-rotation")

	sessionA, sessionB := clientA.conn, clientB.conn
	if sessionA == nil || sessionB == nil {
		t.Fatal("clients did not establish QUIC sessions")
	}

	closed := env.service.UpdateUsersWithSessionRevocation(
		[]testUserIdentity{{user: "user-a", generation: 2}, {user: "user-b", generation: 1}},
		[]string{"password-a-v2", "password-b"},
	)
	if closed != 1 {
		t.Fatalf("revoked session count = %d, want only the rotated user", closed)
	}

	select {
	case <-sessionA.quicConn.Context().Done():
	case <-time.After(testIOTimeout):
		t.Fatal("rotated user kept its QUIC session open")
	}
	if _, err := sessionA.quicConn.OpenStream(); err == nil {
		t.Fatal("rotated user opened a new stream on the revoked QUIC session")
	}
	if err := readWithDeadline(streamA); err == nil {
		t.Fatal("rotated user kept its TCP stream alive")
	}
	if err := probePacketConn(packetA, "a-udp-after-rotation"); err == nil {
		t.Fatal("rotated user kept its UDP association alive")
	}

	select {
	case <-sessionB.quicConn.Context().Done():
		t.Fatal("revocation closed the unaffected user's QUIC session")
	default:
	}
	assertStreamEchoes(t, streamB, "b-after-rotation")
	assertPacketEchoes(t, packetB, "b-udp-after-rotation")

	assertStreamEchoes(t, dialTestStream(t, env.newClient(t, "password-a-v2")), "a-after-rotation")

	ctx, cancel := context.WithTimeout(context.Background(), testIOTimeout)
	defer cancel()
	if _, err := env.newClient(t, "password-a-v1").DialConn(ctx, testEchoDestination); err == nil {
		t.Fatal("the replaced credential still authenticated")
	}
}

// TestServiceKeepsSessionsWhenUserListIsReordered pins the identity stability
// requirement: the authenticated identity must not depend on list order.
func TestServiceKeepsSessionsWhenUserListIsReordered(t *testing.T) {
	env := startTestService(t, []testUserIdentity{
		{user: "user-a", generation: 1},
		{user: "user-b", generation: 1},
	}, []string{"password-a", "password-b"})

	clientA := env.newClient(t, "password-a")
	clientB := env.newClient(t, "password-b")
	streamA := dialTestStream(t, clientA)
	streamB := dialTestStream(t, clientB)
	assertStreamEchoes(t, streamA, "a-before-reorder")
	assertStreamEchoes(t, streamB, "b-before-reorder")

	closed := env.service.UpdateUsersWithSessionRevocation(
		[]testUserIdentity{{user: "user-b", generation: 1}, {user: "user-a", generation: 1}},
		[]string{"password-b", "password-a"},
	)
	if closed != 0 {
		t.Fatalf("reordering closed %d sessions, want 0", closed)
	}
	assertStreamEchoes(t, streamA, "a-after-reorder")
	assertStreamEchoes(t, streamB, "b-after-reorder")
}

// TestServiceRegistryDropsSessionsAfterClose guards against leaking session
// bookkeeping and per-session goroutines when an inbound is torn down. An
// inbound cancels the service context before closing the listener.
func TestServiceRegistryDropsSessionsAfterClose(t *testing.T) {
	env := startTestService(t, []testUserIdentity{
		{user: "user-a", generation: 1},
		{user: "user-b", generation: 1},
	}, []string{"password-a", "password-b"})

	assertStreamEchoes(t, dialTestStream(t, env.newClient(t, "password-a")), "a")
	assertStreamEchoes(t, dialTestStream(t, env.newClient(t, "password-b")), "b")
	if got := testSessionCount(env.service); got != 2 {
		t.Fatalf("registered sessions = %d, want 2", got)
	}

	env.cancel()
	if err := env.service.Close(); err != nil {
		t.Fatalf("close service: %v", err)
	}

	deadline := time.Now().Add(testIOTimeout)
	for time.Now().Before(deadline) {
		if testSessionCount(env.service) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("registered sessions = %d after close, want 0", testSessionCount(env.service))
}

// TestConcurrentAuthenticationAndUserUpdate exercises the window where a
// handshake reads one authentication snapshot while another goroutine replaces
// it. Either outcome is valid for a single attempt, but the run must stay
// race-free and a session must never survive a revoked identity.
func TestConcurrentAuthenticationAndUserUpdate(t *testing.T) {
	env := startTestService(t, []testUserIdentity{
		{user: "user-a", generation: 1},
	}, []string{"password-a"})

	updated := make(chan struct{})
	go func() {
		defer close(updated)
		for generation := 2; generation <= 12; generation++ {
			env.service.UpdateUsersWithSessionRevocation(
				[]testUserIdentity{{user: "user-a", generation: generation}},
				[]string{"password-a"},
			)
			time.Sleep(time.Millisecond)
		}
	}()

	for attempt := 0; attempt < 12; attempt++ {
		client := env.newClient(t, "password-a")
		ctx, cancel := context.WithTimeout(context.Background(), testIOTimeout)
		conn, err := client.DialConn(ctx, testEchoDestination)
		cancel()
		if err == nil {
			_ = conn.Close()
		}
		_ = client.CloseWithError(net.ErrClosed)
	}
	<-updated

	if generation := env.service.users.Load(); len(generation.identities) != 1 {
		t.Fatalf("authentication snapshot holds %d identities, want 1", len(generation.identities))
	}
}

type testServiceEnv struct {
	service   *Service[testUserIdentity]
	address   M.Socksaddr
	clientTLS aTLS.Config
	cancel    context.CancelFunc
}

func startTestService(t *testing.T, users []testUserIdentity, passwords []string) *testServiceEnv {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	service, err := NewService[testUserIdentity](ServiceOptions{
		Context:    ctx,
		Logger:     logger.NOP(),
		TLSConfig:  serverTLS,
		UDPTimeout: 30 * time.Second,
		Handler:    &testEchoHandler{},
		SendBPS:    100 * 1024 * 1024,
		ReceiveBPS: 100 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	service.UpdateUsers(users, passwords)

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	if err := service.Start(packetConn); err != nil {
		_ = packetConn.Close()
		t.Fatalf("start service: %v", err)
	}
	t.Cleanup(func() {
		_ = service.Close()
		_ = packetConn.Close()
	})
	return &testServiceEnv{
		service:   service,
		address:   M.SocksaddrFromNet(packetConn.LocalAddr()).Unwrap(),
		clientTLS: clientTLS,
		cancel:    cancel,
	}
}

func (e *testServiceEnv) newClient(t *testing.T, password string) *Client {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client, err := NewClient(ClientOptions{
		Context:       ctx,
		Dialer:        N.SystemDialer,
		Logger:        logger.NOP(),
		ServerAddress: e.address,
		Password:      password,
		TLSConfig:     e.clientTLS.Clone(),
		SendBPS:       100 * 1024 * 1024,
		ReceiveBPS:    100 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(net.ErrClosed) })
	return client
}

func testSessionCount(service *Service[testUserIdentity]) int {
	service.sessionAccess.Lock()
	defer service.sessionAccess.Unlock()
	return len(service.sessions)
}

func dialTestStream(t *testing.T, client *Client) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testIOTimeout)
	defer cancel()
	conn, err := client.DialConn(ctx, testEchoDestination)
	if err != nil {
		t.Fatalf("dial stream: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func listenTestPacketConn(t *testing.T, client *Client) net.PacketConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testIOTimeout)
	defer cancel()
	packetConn, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	t.Cleanup(func() { _ = packetConn.Close() })
	return packetConn
}

func assertStreamEchoes(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write %q: %v", payload, err)
	}
	buffer := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(testIOTimeout))
	if err := readFull(conn, buffer); err != nil {
		t.Fatalf("read echo of %q: %v", payload, err)
	}
	if string(buffer) != payload {
		t.Fatalf("echo = %q, want %q", buffer, payload)
	}
}

func assertPacketEchoes(t *testing.T, conn net.PacketConn, payload string) {
	t.Helper()
	if err := probePacketConn(conn, payload); err != nil {
		t.Fatalf("packet echo of %q: %v", payload, err)
	}
}

func probePacketConn(conn net.PacketConn, payload string) error {
	if _, err := conn.WriteTo([]byte(payload), testEchoDestination.UDPAddr()); err != nil {
		return err
	}
	buffer := make([]byte, 2048)
	_ = conn.SetReadDeadline(time.Now().Add(testIdleTimeout))
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		return err
	}
	if string(buffer[:n]) != payload {
		return net.ErrClosed
	}
	return nil
}

func readWithDeadline(conn net.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(testIdleTimeout))
	buffer := make([]byte, 1)
	_, err := conn.Read(buffer)
	return err
}

func readFull(conn net.Conn, buffer []byte) error {
	read := 0
	for read < len(buffer) {
		n, err := conn.Read(buffer[read:])
		read += n
		if err != nil {
			return err
		}
	}
	return nil
}

type testEchoHandler struct{}

func (h *testEchoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer func() {
			_ = conn.Close()
			if onClose != nil {
				onClose(nil)
			}
		}()
		buffer := make([]byte, 2048)
		for {
			n, err := conn.Read(buffer)
			if n > 0 {
				if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

func (h *testEchoHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer func() {
			_ = conn.Close()
			if onClose != nil {
				onClose(nil)
			}
		}()
		for {
			buffer := buf.NewSize(2048)
			destination, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			if err := conn.WritePacket(buffer, destination); err != nil {
				return
			}
		}
	}()
}

func testTLSConfigs(t *testing.T) (aTLS.ServerConfig, aTLS.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acp-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		DNSNames:              []string{"acp-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)

	serverConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: certificate}},
	}
	clientConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: "acp-test",
	}
	return &testTLSConfig{config: serverConfig}, &testTLSConfig{config: clientConfig}
}

// testTLSConfig is the minimal aTLS.Config / aTLS.ServerConfig adapter over a
// standard library configuration; sing only ships the interfaces.
type testTLSConfig struct {
	config *tls.Config
}

func (c *testTLSConfig) ServerName() string                  { return c.config.ServerName }
func (c *testTLSConfig) SetServerName(serverName string)     { c.config.ServerName = serverName }
func (c *testTLSConfig) NextProtos() []string                { return c.config.NextProtos }
func (c *testTLSConfig) SetNextProtos(nextProto []string)    { c.config.NextProtos = nextProto }
func (c *testTLSConfig) STDConfig() (*aTLS.STDConfig, error) { return c.config, nil }
func (c *testTLSConfig) Start() error                        { return nil }
func (c *testTLSConfig) Close() error                        { return nil }

func (c *testTLSConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	return tls.Client(conn, c.config), nil
}

func (c *testTLSConfig) Server(conn net.Conn) (aTLS.Conn, error) {
	return tls.Server(conn, c.config), nil
}

func (c *testTLSConfig) Clone() aTLS.Config {
	return &testTLSConfig{config: c.config.Clone()}
}
