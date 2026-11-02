package v2rayxhttp

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxSessions    = 1024
	maxQueuedBytes = 64 << 20
	pairingTimeout = 30 * time.Second
)

// Sessions belong to one listener. Both GET-first and POST-first peers are
// valid; a half-open session expires even if the peer never sends its mate.
type sessions struct {
	mu       sync.Mutex
	entries  map[string]*uploadSession
	closed   bool
	buffered atomic.Int64
}

func (r *sessions) get(id string) (*uploadSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, net.ErrClosed
	}
	if s := r.entries[id]; s != nil {
		return s, nil
	}
	if len(r.entries) >= maxSessions {
		return nil, errors.New("too many XHTTP sessions")
	}
	if r.entries == nil {
		r.entries = make(map[string]*uploadSession)
	}
	s := &uploadSession{id: id, owner: r, packets: make(map[uint64][]byte), done: make(chan struct{}), uploadEOF: make(chan struct{})}
	s.ready = sync.NewCond(&s.mu)
	r.entries[id] = s
	s.timer = time.AfterFunc(pairingTimeout, func() { s.finish(true) })
	return s, nil
}

func (r *sessions) close() {
	r.mu.Lock()
	r.closed = true
	entries := r.entries
	r.entries = nil
	r.mu.Unlock()
	for _, s := range entries {
		s.Close()
	}
}

type uploadSession struct {
	id              string
	owner           *sessions
	mu              sync.Mutex
	ready           *sync.Cond
	timer           *time.Timer
	drain           *time.Timer
	drainUntil      time.Time
	download        bool
	kind            string
	body            io.ReadCloser
	packets         map[uint64][]byte
	next            uint64
	queued          int64
	done, uploadEOF chan struct{}
	eofOnce         sync.Once
	closed          bool
}

func (s *uploadSession) pairLocked() {
	if s.download && s.kind != "" {
		s.timer.Stop()
	}
	s.ready.Broadcast()
}

func (s *uploadSession) attachDownload() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.download {
		return false
	}
	s.download = true
	s.pairLocked()
	return true
}

func (s *uploadSession) attachStream(body io.ReadCloser) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.kind != "" {
		return false
	}
	s.kind = ModeStreamUp
	s.body = body
	s.pairLocked()
	return true
}

func (s *uploadSession) push(seq uint64, b []byte, limit int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.kind == ModeStreamUp {
		return errors.New("upload mode already selected")
	}
	if seq < s.next {
		return nil
	}
	if _, ok := s.packets[seq]; ok {
		return nil
	}
	if seq-s.next >= uint64(limit) {
		return errors.New("packet outside reorder window")
	}
	size := int64(len(b))
	if s.owner.buffered.Add(size) > maxQueuedBytes {
		s.owner.buffered.Add(-size)
		return errors.New("XHTTP upload buffer full")
	}
	if s.drain != nil {
		s.drainUntil = time.Now().Add(pairingTimeout)
	}
	s.queued += size
	s.kind = ModePacketUp
	s.packets[seq] = b
	s.pairLocked()
	return nil
}

// Once a split download has sent END_STREAM, its separate upload may still
// have a tail in flight. Packet-up has no upload FIN: expire a detached
// session after an idle interval, extending it while new data arrives.
func (s *uploadSession) detachDownload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed && s.drain == nil {
		s.drainUntil = time.Now().Add(pairingTimeout)
		s.drain = time.AfterFunc(pairingTimeout, s.expireDrain)
	}
}

func (s *uploadSession) expireDrain() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if remaining := time.Until(s.drainUntil); remaining > 0 {
		s.drain.Reset(remaining)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.Close()
}

func (s *uploadSession) Read(p []byte) (int, error) {
	s.mu.Lock()
	for !s.closed {
		if s.body != nil {
			body := s.body
			s.mu.Unlock()
			n, err := body.Read(p)
			if n > 0 {
				s.mu.Lock()
				if s.drain != nil {
					s.drainUntil = time.Now().Add(pairingTimeout)
				}
				s.mu.Unlock()
			}
			if err != nil {
				s.eofOnce.Do(func() { close(s.uploadEOF) })
			}
			return n, err
		}
		if packet, ok := s.packets[s.next]; ok {
			n := copy(p, packet)
			if n == len(packet) {
				delete(s.packets, s.next)
				s.next++
			} else {
				s.packets[s.next] = packet[n:]
			}
			s.queued -= int64(n)
			s.owner.buffered.Add(-int64(n))
			if n > 0 {
				s.mu.Unlock()
				return n, nil
			}
			continue
		}
		s.ready.Wait()
	}
	s.mu.Unlock()
	return 0, net.ErrClosed
}

func (s *uploadSession) Close() error { return s.finish(false) }

func (s *uploadSession) finish(unpairedOnly bool) error {
	s.mu.Lock()
	if s.closed || (unpairedOnly && s.download && s.kind != "") {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.drain != nil {
		s.drain.Stop()
	}
	s.timer.Stop()
	close(s.done)
	s.ready.Broadcast()
	body := s.body
	s.owner.buffered.Add(-s.queued)
	s.packets = nil
	s.mu.Unlock()
	s.owner.mu.Lock()
	if s.owner.entries[s.id] == s {
		delete(s.owner.entries, s.id)
	}
	s.owner.mu.Unlock()
	if body != nil {
		return body.Close()
	}
	return nil
}
