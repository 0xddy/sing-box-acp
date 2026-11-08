package naive

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type deadlineWriter struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *deadlineWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func TestCompletedWriteDoesNotExpireIdleTunnel(t *testing.T) {
	w := &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
	r := &http.Request{Body: io.NopCloser(strings.NewReader(""))}
	stream := newHTTPStream(r, w, http.NewResponseController(w), nil)
	if _, err := stream.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if len(w.deadlines) != 2 || w.deadlines[0].IsZero() || !w.deadlines[1].IsZero() {
		t.Fatal("write deadline leaked into the following idle period")
	}
	_ = stream.abort()
	_ = stream.abort()
	if len(w.deadlines) != 3 || w.deadlines[2].IsZero() || w.deadlines[2].After(time.Now()) {
		t.Fatal("revocation must interrupt the stream exactly once")
	}
}
