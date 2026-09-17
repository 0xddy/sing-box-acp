package vless

import (
	"context"
	"errors"
	"io"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"
)

type inboundConnectionLogRecorder struct {
	debugCalls int
	errorCalls int
}

func (r *inboundConnectionLogRecorder) DebugContext(context.Context, ...any) {
	r.debugCalls++
}

func (r *inboundConnectionLogRecorder) ErrorContext(context.Context, ...any) {
	r.errorCalls++
}

func TestLogInboundConnectionErrorDowngradesWrappedEOF(t *testing.T) {
	recorder := new(inboundConnectionLogRecorder)
	err := E.Cause(E.Cause(io.EOF, "read frame header"), "mux connection closed")
	logInboundConnectionError(recorder, context.Background(), err, E.IsClosedOrCanceled(err), "process connection")
	if recorder.debugCalls != 1 || recorder.errorCalls != 0 {
		t.Fatalf("log calls = debug %d, error %d", recorder.debugCalls, recorder.errorCalls)
	}
}

func TestLogInboundConnectionErrorKeepsProtocolFailure(t *testing.T) {
	recorder := new(inboundConnectionLogRecorder)
	err := errors.New("bad multiplex frame")
	logInboundConnectionError(recorder, context.Background(), err, E.IsClosedOrCanceled(err), "process connection")
	if recorder.debugCalls != 0 || recorder.errorCalls != 1 {
		t.Fatalf("log calls = debug %d, error %d", recorder.debugCalls, recorder.errorCalls)
	}
}
