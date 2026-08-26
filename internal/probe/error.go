package probe

import (
	"errors"

	"github.com/cumakurt/garga/internal/transport"
)

// ErrorKind classifies the layer that prevented a probe result.
type ErrorKind string

const (
	ErrorInvalidEndpoint ErrorKind = "invalid_endpoint"
	ErrorCanceled        ErrorKind = "canceled"
	ErrorTimeout         ErrorKind = "timeout"
	ErrorTCP             ErrorKind = "tcp"
	ErrorTLS             ErrorKind = "tls"
	ErrorHTTP            ErrorKind = "http"
)

// Error retains a safe cause while omitting endpoint and request details.
type Error struct {
	kind  ErrorKind
	cause error
}

func (err *Error) Error() string {
	switch err.kind {
	case ErrorInvalidEndpoint:
		return "probe failed: invalid endpoint or request"
	case ErrorCanceled:
		return "probe failed: operation canceled"
	case ErrorTimeout:
		return "probe failed: operation timed out"
	case ErrorTCP:
		return "probe failed: TCP connection error"
	case ErrorTLS:
		return "probe failed: TLS error"
	default:
		return "probe failed: HTTP error"
	}
}

func (err *Error) Unwrap() error {
	return err.cause
}

func (err *Error) Kind() ErrorKind {
	return err.kind
}

// KindOf returns the classification of a probe error.
func KindOf(err error) (ErrorKind, bool) {
	var probeError *Error
	if !errors.As(err, &probeError) {
		return "", false
	}
	return probeError.kind, true
}

func classifyError(err error) *Error {
	kind := ErrorHTTP
	if transportKind, ok := transport.KindOf(err); ok {
		switch transportKind {
		case transport.ErrorInvalidRequest:
			kind = ErrorInvalidEndpoint
		case transport.ErrorCanceled:
			kind = ErrorCanceled
		case transport.ErrorTimeout:
			kind = ErrorTimeout
		case transport.ErrorDNS, transport.ErrorConnect, transport.ErrorNetwork:
			kind = ErrorTCP
		case transport.ErrorTLS:
			kind = ErrorTLS
		case transport.ErrorRedirect, transport.ErrorProtocol, transport.ErrorRead, transport.ErrorResponseTooLarge:
			kind = ErrorHTTP
		}
	}
	return &Error{kind: kind, cause: err}
}
