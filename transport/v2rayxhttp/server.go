package v2rayxhttp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

type Server struct {
	http     *http.Server
	cancel   context.CancelFunc
	tls      tls.ServerConfig
	opts     Options
	codec    *codec
	handler  adapter.V2RayServerTransportHandler
	sessions sessions
}

func NewServer(ctx context.Context, opts Options, config tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, error) {
	opts, err := normalizeOptions(opts, config)
	if err != nil {
		return nil, err
	}
	if opts.DownloadSettings != nil {
		return nil, fmt.Errorf("XHTTP download_settings is an outbound option")
	}
	config.SetNextProtos([]string{"h2"})
	ctx, cancel := context.WithCancel(ctx)
	s := &Server{cancel: cancel, tls: config, opts: opts, codec: newCodec(opts), handler: handler}
	protocols := new(http.Protocols)
	// The listener performs TLS/REALITY before exposing the h2 preface.
	protocols.SetUnencryptedHTTP2(true)
	maxHeader := int(opts.ServerMaxHeaderBytes)
	if maxHeader == 0 {
		maxHeader = 16 << 10
	}
	s.http = &http.Server{Handler: s, Protocols: protocols, ReadHeaderTimeout: C.TCPTimeout, MaxHeaderBytes: maxHeader, BaseContext: func(net.Listener) context.Context { return ctx }}
	return s, nil
}

func (s *Server) Network() []string { return []string{N.NetworkTCP} }

func (s *Server) Serve(l net.Listener) error { return s.http.Serve(aTLS.NewListener(l, s.tls)) }

func (s *Server) ServePacket(net.PacketConn) error { return os.ErrInvalid }

func (s *Server) Close() error { s.cancel(); s.sessions.close(); return s.http.Close() }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil && !strings.Contains(s.opts.Host, ":") {
		host = h
	}
	id, seq, ok := s.codec.extractMetaFromRequest(r)
	if r.ProtoMajor != 2 || !ok || len(id) > 256 || (s.opts.Host != "" && !strings.EqualFold(s.opts.Host, host)) {
		http.NotFound(w, r)
		return
	}
	if !s.codec.validatePadding(s.codec.extractPaddingFromRequest(r)) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	for name, values := range s.opts.Headers {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	s.codec.applyPaddingToResponseHeader(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	if id == "" {
		if seq != "" || r.Method != s.opts.Method || !s.allows(ModeStreamOne) {
			http.NotFound(w, r)
			return
		}
		s.serveDownload(w, r, r.Body)
		return
	}
	switch {
	case seq != "" && r.Method == s.opts.Method && s.allows(ModePacketUp):
		s.servePacket(w, r, id, seq)
	case r.Method == http.MethodGet && seq == "" && (s.allows(ModePacketUp) || s.allows(ModeStreamUp)):
		session, err := s.sessions.get(id)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !session.attachDownload() {
			w.WriteHeader(http.StatusConflict)
			return
		}
		s.serveDownload(w, r, session)
	case seq == "" && r.Method == s.opts.Method && s.allows(ModeStreamUp):
		s.serveUpload(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) allows(mode string) bool { return s.opts.Mode == ModeAuto || s.opts.Mode == mode }

func (s *Server) servePacket(w http.ResponseWriter, r *http.Request, id, rawSeq string) {
	seq, err := strconv.ParseUint(rawSeq, 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	limit := int64(s.codec.maxEachPostBytes.To)
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	payload, err := s.codec.decodeUplinkPayload(r, body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if int64(len(payload)) > limit {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	session, err := s.sessions.get(id)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	window := int(s.opts.ScMaxBufferedPosts)
	if window == 0 {
		window = 30
	}
	if err := session.push(seq, payload, window); err != nil {
		w.WriteHeader(http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) serveUpload(w http.ResponseWriter, r *http.Request, id string) {
	session, err := s.sessions.get(id)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if !session.attachStream(r.Body) {
		w.WriteHeader(http.StatusConflict)
		return
	}
	response := http.NewResponseController(w)
	if response.Flush() != nil {
		session.Close()
		return
	}
	interval := orRange(s.opts.ScStreamUpServerSecs, Range{From: 20, To: 80})
	var timer *time.Timer
	var tick <-chan time.Time
	if interval.To > 0 {
		timer = time.NewTimer(time.Duration(max(1, rangeRand(interval))) * time.Second)
		defer timer.Stop()
		tick = timer.C
	}
	for {
		select {
		case <-session.done:
			return
		case <-session.uploadEOF:
			return
		case <-r.Context().Done():
			session.Close()
			return
		case <-tick:
			if _, err = io.WriteString(w, strings.Repeat("X", int(rangeRand(s.codec.xpadRange)))); err != nil || response.Flush() != nil {
				session.Close()
				return
			}
			timer.Reset(time.Duration(max(1, rangeRand(interval))) * time.Second)
		}
	}
}

func (s *Server) serveDownload(w http.ResponseWriter, r *http.Request, body io.ReadCloser) {
	if !s.opts.NoSSEHeader {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	response := http.NewResponseController(w)
	if response.Flush() != nil {
		body.Close()
		return
	}
	src := M.ParseSocksaddr(r.RemoteAddr)
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	// A split upload can outlive its GET. The logical context is canceled on
	// full close, while the ResponseWriter stays on the HTTP handler goroutine.
	ctx, cancel := context.WithCancel(context.WithoutCancel(r.Context()))
	conn, input, output := newStream(local, src, func() { cancel(); body.Close() })
	defer output.Close()
	stop := context.AfterFunc(r.Context(), func() { conn.Close() })
	readDone := make(chan struct{})
	go func() { defer close(readDone); conn.receive(input, body) }()
	go s.handler.NewConnectionEx(ctx, conn, src, M.Socksaddr{}, func(error) { conn.Close() })
	session, split := body.(*uploadSession)
	if split {
		go func() {
			select {
			case <-session.done:
				conn.Close()
			case <-ctx.Done():
			}
		}()
	}
	_, err := io.Copy(flushingWriter{w, response}, output)
	if err == nil && split && stop() {
		session.detachDownload()
		return
	}
	if err == nil && !split {
		// net/http resets the unfinished POST if we return after a download FIN.
		<-readDone
	}
	stop()
	conn.Close()
}

type flushingWriter struct {
	io.Writer
	controller *http.ResponseController
}

func (w flushingWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if err == nil {
		err = w.controller.Flush()
	}
	return n, err
}
