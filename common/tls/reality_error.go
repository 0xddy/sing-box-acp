package tls

import "errors"

const realityInvalidConnectionMessage = "REALITY: processed invalid connection"

var errRealityInvalidConnection = errors.New(realityInvalidConnectionMessage)

type realityInvalidConnectionError struct {
	cause error
}

func (e *realityInvalidConnectionError) Error() string {
	return e.cause.Error()
}

func (e *realityInvalidConnectionError) Unwrap() error {
	return e.cause
}

func (e *realityInvalidConnectionError) Is(target error) bool {
	return target == errRealityInvalidConnection
}

// normalizeRealityServerError converts the untyped result returned by uTLS
// after it has handled an invalid REALITY probe into a locally typed error.
// Keep the comparison exact so unrelated handshake failures remain visible.
func normalizeRealityServerError(err error) error {
	if err == nil || errors.Is(err, errRealityInvalidConnection) {
		return err
	}
	if err.Error() != realityInvalidConnectionMessage {
		return err
	}
	return &realityInvalidConnectionError{cause: err}
}

// IsRealityInvalidConnection reports whether REALITY already handled and
// rejected a connection during its validation.
func IsRealityInvalidConnection(err error) bool {
	return errors.Is(err, errRealityInvalidConnection)
}
