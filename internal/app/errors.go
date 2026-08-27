package app

import (
	"errors"
	"fmt"
)

// ErrInvalidInput marks operator-supplied target, configuration, or signature problems.
var ErrInvalidInput = errors.New("invalid scan input")

// Error is a scan-orchestration failure with a secret-safe public message.
type Error struct {
	message string
	cause   error
	invalid bool
}

func (err *Error) Error() string {
	if err == nil {
		return "scan failed"
	}
	return err.message
}

func (err *Error) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func (err *Error) Is(target error) bool {
	if err == nil {
		return false
	}
	if target == ErrInvalidInput {
		return err.invalid
	}
	return false
}

func invalidError(message string, cause error) error {
	return &Error{message: message, cause: cause, invalid: true}
}

func internalError(message string, cause error) error {
	if cause == nil {
		return &Error{message: message}
	}
	return &Error{message: message, cause: fmt.Errorf("%s: %w", message, cause)}
}
