package naive

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio/deadline"
)

func TestUserFlowPreservesStreamSniffing(t *testing.T) {
	for _, protocol := range []int{2, 3} {
		t.Run("http"+strconv.Itoa(protocol), func(t *testing.T) {
			payload := []byte("GET / HTTP/1.1\r\nHost: sniff.example\r\n\r\n")
			wire := append([]byte{byte(len(payload) >> 8), byte(len(payload)), 0}, payload...)
			request := &http.Request{ProtoMajor: protocol, Body: io.NopCloser(bytes.NewReader(wire))}
			writer := httptest.NewRecorder()
			stream := newHTTPStream(request, writer, http.NewResponseController(writer), nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			flow := &userFlow{ctx: ctx, cancel: cancel}
			if !flow.attach(stream) {
				t.Fatal("flow attachment failed")
			}
			var conn net.Conn = flow
			if deadline.NeedAdditionalReadDeadline(conn) {
				conn = deadline.NewConn(conn)
			}
			defer conn.Close()
			buffer := buf.NewPacket()
			defer buffer.Release()
			metadata := new(adapter.InboundContext)
			err := sniff.PeekStream(ctx, metadata, conn, nil, buffer, time.Second, sniff.HTTPHost)
			if err != nil || metadata.Domain != "sniff.example" || metadata.Protocol != "http" {
				t.Fatalf("sniff: domain=%q protocol=%q error=%v", metadata.Domain, metadata.Protocol, err)
			}
		})
	}
}

func TestUserFlowSniffTimeoutAndRevocation(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	response := httptest.NewRecorder()
	stream := newHTTPStream(&http.Request{Body: reader}, response, http.NewResponseController(response), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	flow := &userFlow{ctx: ctx, cancel: cancel}
	if !flow.attach(stream) {
		t.Fatal("flow attachment failed")
	}
	var conn net.Conn = flow
	if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewConn(conn)
	}
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		buffer := buf.NewPacket()
		defer buffer.Release()
		done <- sniff.PeekStream(ctx, new(adapter.InboundContext), conn, nil, buffer, 20*time.Millisecond, sniff.HTTPHost)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected sniff timeout, got %v", err)
		}
	case <-time.After(3 * time.Second):
		_ = flow.abort()
		<-done
		t.Fatal("sniff did not honor its deadline")
	}
	if err := flow.abort(); err != nil || ctx.Err() != context.Canceled {
		t.Fatalf("revoke after timed-out sniff: %v, context: %v", err, ctx.Err())
	}
}

func TestUserFlowPreservesSocketDeadlines(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	flow := &userFlow{ctx: ctx, cancel: cancel}
	if !flow.attach(&naiveConn{Conn: &writeProgressConn{Conn: left}}) {
		t.Fatal("flow attachment failed")
	}
	defer flow.Close()
	if deadline.NeedAdditionalReadDeadline(flow) {
		t.Fatal("HTTP/1 socket already supports read deadlines")
	}
	if err := flow.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := flow.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("socket read did not expire: %v", err)
	}
}
