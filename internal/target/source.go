package target

import (
	"context"

	"github.com/cumakurt/garga/internal/model"
)

// Source produces canonical targets on demand. Implementations are intended for one consumer;
// callers must close a source and must not call Next concurrently.
type Source interface {
	Next(ctx context.Context) (model.Target, error)
	Close() error
}

type sourceError struct {
	message string
	cause   error
}

func (err *sourceError) Error() string {
	return err.message
}

func (err *sourceError) Unwrap() error {
	return err.cause
}

func newSourceError(message string, cause error) error {
	return &sourceError{message: message, cause: cause}
}
