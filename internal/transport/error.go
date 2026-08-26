package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
)

// ErrorKind is a stable, credential-safe transport failure classification.
type ErrorKind string

const (
	ErrorInvalidRequest   ErrorKind = "invalid_request"
	ErrorCanceled         ErrorKind = "canceled"
	ErrorTimeout          ErrorKind = "timeout"
	ErrorDNS              ErrorKind = "dns"
	ErrorTLS              ErrorKind = "tls"
	ErrorConnect          ErrorKind = "connect"
	ErrorRedirect         ErrorKind = "redirect"
	ErrorProtocol         ErrorKind = "protocol"
	ErrorNetwork          ErrorKind = "network"
	ErrorRead             ErrorKind = "read"
	ErrorResponseTooLarge ErrorKind = "response_too_large"
)

var (
	errInvalidRequest   = errors.New("invalid request")
	errRedirectLimit    = errors.New("redirect limit reached")
	errResponseTooLarge = errors.New("response exceeded configured limit")
)

// Error carries a typed failure and its original cause without formatting request metadata.
type Error struct {
	kind      ErrorKind
	operation string
	cause     error
}

func (err *Error) Error() string {
	return "transport " + err.operation + " failed: " + safeKindMessage(err.kind)
}

func (err *Error) Unwrap() error {
	return err.cause
}

func (err *Error) Kind() ErrorKind {
	return err.kind
}

func safeKindMessage(kind ErrorKind) string {
	switch kind {
	case ErrorInvalidRequest:
		return "invalid request"
	case ErrorCanceled:
		return "operation canceled"
	case ErrorTimeout:
		return "operation timed out"
	case ErrorDNS:
		return "name resolution failed"
	case ErrorTLS:
		return "TLS negotiation or verification failed"
	case ErrorConnect:
		return "connection failed"
	case ErrorRedirect:
		return "redirect limit reached"
	case ErrorProtocol:
		return "invalid HTTP response"
	case ErrorRead:
		return "response read failed"
	case ErrorResponseTooLarge:
		return "response exceeded configured limit"
	default:
		return "network operation failed"
	}
}

// KindOf returns a stable failure kind for transport errors.
func KindOf(err error) (ErrorKind, bool) {
	var transportError *Error
	if !errors.As(err, &transportError) {
		return "", false
	}
	return transportError.kind, true
}

func classifyRequestError(err error) *Error {
	cause := stripURLError(err)
	kind := ErrorNetwork

	switch {
	case errors.Is(cause, context.Canceled):
		kind = ErrorCanceled
	case errors.Is(cause, context.DeadlineExceeded):
		kind = ErrorTimeout
	case errors.Is(cause, errRedirectLimit):
		kind = ErrorRedirect
	case errors.Is(cause, errInvalidRequest):
		kind = ErrorRedirect
	case isTLSError(cause):
		kind = ErrorTLS
	default:
		var dnsError *net.DNSError
		var netError net.Error
		var opError *net.OpError
		switch {
		case errors.As(cause, &dnsError):
			kind = ErrorDNS
		case errors.As(cause, &netError) && netError.Timeout():
			kind = ErrorTimeout
		case errors.As(cause, &opError):
			if opError.Op == "dial" || opError.Op == "connect" {
				kind = ErrorConnect
			} else {
				kind = ErrorNetwork
			}
		default:
			kind = ErrorProtocol
		}
	}

	return &Error{kind: kind, operation: "request", cause: cause}
}

func stripURLError(err error) error {
	var urlError *url.Error
	if errors.As(err, &urlError) && urlError.Err != nil {
		return urlError.Err
	}
	return err
}

func isTLSError(err error) bool {
	var certificateError *tls.CertificateVerificationError
	var recordHeaderError tls.RecordHeaderError
	var unknownAuthorityError x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var certificateInvalidError x509.CertificateInvalidError
	return errors.As(err, &certificateError) ||
		errors.As(err, &recordHeaderError) ||
		errors.As(err, &unknownAuthorityError) ||
		errors.As(err, &hostnameError) ||
		errors.As(err, &certificateInvalidError)
}
