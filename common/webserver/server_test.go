package webserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"golang.org/x/net/http2"
)

func TestHTTPVersionsAndOwnership(t *testing.T) {
	for _, protocol := range []string{"", "http/1.1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			s := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil {
					t.Error("TLS state lost")
				}
				w.Write([]byte("website"))
			}), log.NewNOPFactory().Logger())
			if err := s.Start(); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			server, client := net.Pipe()
			defer client.Close()
			client.SetDeadline(time.Now().Add(5 * time.Second))
			var closed atomic.Int32
			state := tls.ConnectionState{NegotiatedProtocol: protocol, Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, HandshakeComplete: true}
			if err := s.Serve(server, state, func(error) { closed.Add(1) }); err != nil {
				t.Fatal(err)
			}
			if protocol == "h2" {
				transport := &http2.Transport{}
				cc, err := transport.NewClientConn(client)
				if err != nil {
					t.Fatal(err)
				}
				var wg sync.WaitGroup
				for i := 0; i < 8; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer func() {
							if v := recover(); v != nil {
								t.Error(v)
							}
						}()
						r, _ := http.NewRequestWithContext(context.Background(), "GET", "https://example.com/", nil)
						response, err := cc.RoundTrip(r)
						if err != nil {
							t.Error(err)
							return
						}
						defer response.Body.Close()
						body, err := io.ReadAll(response.Body)
						if err != nil || string(body) != "website" || response.ProtoMajor != 2 {
							t.Error("HTTP/2 response", err)
						}
					}()
				}
				wg.Wait()
			} else {
				reader := bufio.NewReader(client)
				for i := 0; i < 2; i++ {
					if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
						t.Fatal(err)
					}
					response, err := http.ReadResponse(reader, nil)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil || string(body) != "website" {
						t.Fatal("HTTP/1 response", err)
					}
				}
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if closed.Load() != 1 {
				t.Fatalf("callback count %d", closed.Load())
			}
		})
	}
}

func TestCloseRejectsHandoffAndCancelsRequests(t *testing.T) {
	started, canceled := make(chan struct{}), make(chan struct{})
	s := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(canceled) }), log.NewNOPFactory().Logger())
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	server, client := net.Pipe()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.Serve(server, tls.ConnectionState{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request handler did not start")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("request context not canceled")
	}
	rejected, peer := net.Pipe()
	defer rejected.Close()
	defer peer.Close()
	if err := s.Serve(rejected, tls.ConnectionState{}, nil); err == nil {
		t.Fatal("handoff accepted after close")
	}
}

func TestConnectionLimitAndHeaderTimeout(t *testing.T) {
	s := New(http.NotFoundHandler(), log.NewNOPFactory().Logger())
	s.http.ReadHeaderTimeout = 50 * time.Millisecond
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	server, client := net.Pipe()
	defer client.Close()
	closed := make(chan struct{})
	if err := s.Serve(server, tls.ConnectionState{}, func(error) { close(closed) }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("header timeout did not release connection")
	}
	// Keep idle HTTP/2 connections below their preface timeout while exercising
	// the service-wide connection cap. Rejected connections remain caller-owned.
	state := tls.ConnectionState{NegotiatedProtocol: "h2", Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256}
	for i := 0; i < maxConnections; i++ {
		server, client := net.Pipe()
		defer client.Close()
		if err := s.Serve(server, state, nil); err != nil {
			server.Close()
			t.Fatal(err)
		}
	}
	rejected, peer := net.Pipe()
	defer rejected.Close()
	defer peer.Close()
	var callback atomic.Int32
	if err := s.Serve(rejected, state, func(error) { callback.Add(1) }); err == nil {
		t.Fatal("connection cap ignored")
	}
	if callback.Load() != 0 {
		t.Fatal("failed handoff invoked callback")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentCloseAndHandoff(t *testing.T) {
	s := New(http.NotFoundHandler(), log.NewNOPFactory().Logger())
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var accepted, callbacks atomic.Int32
	// Keep one accepted connection live before racing Close with more handoffs;
	// otherwise an all-rejected run could pass without exercising ownership.
	server, client := net.Pipe()
	defer client.Close()
	if err := s.Serve(server, tls.ConnectionState{}, func(error) { callbacks.Add(1) }); err != nil {
		t.Fatal(err)
	}
	accepted.Add(1)
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	start := make(chan struct{})
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if value := recover(); value != nil {
					t.Error(value)
				}
			}()
			<-start
			server, client := net.Pipe()
			defer client.Close()
			if err := s.Serve(server, tls.ConnectionState{}, func(error) { callbacks.Add(1) }); err != nil {
				server.Close()
			} else {
				accepted.Add(1)
			}
		}()
	}
	close(start)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if accepted.Load() != callbacks.Load() {
		t.Fatalf("accepted=%d callbacks=%d", accepted.Load(), callbacks.Load())
	}
}
