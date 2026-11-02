// Copyright (C) 2025  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package internal_test

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/internal"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/internal/testtool"
)

// Verify first read and first write can race without losing either the
// server greeting or the client's payload, or sending a second handshake.
func TestConcurrentFirstIO(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	client := internal.NewEarlyConn(peer)
	defer client.Close()
	client.SetRequest(&model.Request{Command: constant.Socks5ConnectCmd, DstAddr: model.AddrSpec{FQDN: "example.org", Port: 22}})
	read := make(chan error, 1)
	write := make(chan error, 1)
	var greeting [2]byte
	go func() { _, err := io.ReadFull(client, greeting[:]); read <- err }()
	go func() { _, err := client.Write([]byte("ping")); write <- err }()
	request, err := model.ReadSocks5Request(raw)
	if err != nil || request.DstAddr.FQDN != "example.org" {
		t.Fatalf("request: %v, %v", request, err)
	}
	if err := model.WriteSocks5Response(raw, constant.Socks5ReplySuccess, model.AddrSpec{IP: net.IPv4zero}); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	var payload [4]byte
	if _, err = io.ReadFull(raw, payload[:]); err != nil || string(payload[:]) != "ping" {
		t.Fatalf("payload: %q, %v", payload, err)
	}
	if err := <-read; err != nil || string(greeting[:]) != "hi" {
		t.Fatalf("greeting: %q, %v", greeting, err)
	}
	if err := <-write; err != nil {
		t.Fatal(err)
	}
}

func TestEarlyConnRequest(t *testing.T) {
	clientConn, serverConn := testtool.BufPipe()

	var wg sync.WaitGroup
	wg.Add(1)

	// Run a fake socks5 server.
	go func() {
		defer wg.Done()
		defer serverConn.Close()

		// Read socks5 request.
		var req model.Request
		if err := req.ReadFromSocks5(serverConn); err != nil {
			t.Errorf("server: failed to read request: %v", err)
			return
		}

		// Send reply using a dummy IPv4 address 0.0.0.0:0.
		reply := []byte{constant.Socks5Version, 0, 0, constant.Socks5IPv4Address, 0, 0, 0, 0, 0, 0}
		if _, err := serverConn.Write(reply); err != nil {
			t.Errorf("server: failed to write reply: %v", err)
			return
		}

		// Read client data ("ping").
		ping := make([]byte, 4)
		if _, err := io.ReadFull(serverConn, ping); err != nil {
			t.Errorf("server: failed to read data: %v", err)
			return
		}
		if string(ping) != "ping" {
			t.Errorf("server: expected client to send 'ping', got '%s'", string(ping))
			return
		}

		// Send server data ("pong").
		if _, err := serverConn.Write([]byte("pong")); err != nil {
			t.Errorf("server: failed to write data: %v", err)
			return
		}
	}()

	// Create client early connection.
	req := &model.Request{
		Command: constant.Socks5ConnectCmd,
		DstAddr: model.AddrSpec{
			FQDN: "example.com",
			Port: 80,
		},
	}
	conn := internal.NewEarlyConn(clientConn)
	conn.SetRequest(req)
	defer conn.Close()

	// The first write triggers the handshake.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("client: failed to write data: %v", err)
	}

	// The server should respond with "pong" after the handshake is complete.
	pong := make([]byte, 4)
	if _, err := io.ReadFull(conn, pong); err != nil {
		t.Fatalf("client: failed to read data: %v", err)
	}

	if string(pong) != "pong" {
		t.Fatalf("client: expected server to send 'pong', got '%s'", string(pong))
	}

	wg.Wait()
}
