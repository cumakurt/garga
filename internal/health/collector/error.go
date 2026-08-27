package collector

import "fmt"

type ErrorKind string

const (
	ErrorConnection     ErrorKind = "connection"
	ErrorAuthentication ErrorKind = "authentication"
	ErrorProduct        ErrorKind = "product"
	ErrorConfiguration  ErrorKind = "configuration"
)

// Error exposes only bounded failure categories and never request URLs or headers.
type Error struct {
	Kind  ErrorKind
	Cause error
}

func (err *Error) Error() string {
	switch err.Kind {
	case ErrorAuthentication:
		return "health collection failed: authentication is required or was rejected"
	case ErrorProduct:
		return "health collection failed: target is not a supported Elasticsearch endpoint"
	case ErrorConfiguration:
		return "health collection failed: configuration is invalid"
	default:
		return "health collection failed: target is unavailable"
	}
}

func (err *Error) Unwrap() error { return err.Cause }

func wrap(kind ErrorKind, cause error) error {
	if cause == nil {
		cause = fmt.Errorf("health collection failed")
	}
	return &Error{Kind: kind, Cause: cause}
}
