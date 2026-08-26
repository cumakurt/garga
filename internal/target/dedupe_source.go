package target

import (
	"context"
	"errors"
	"io"

	"github.com/cumakurt/garga/internal/model"
)

// ErrDeduplicationLimit indicates that exact deduplication exhausted its configured memory
// budget before accepting another unique target.
var ErrDeduplicationLimit = errors.New("target deduplication limit reached")

// DeduplicatingSource suppresses duplicate canonical targets while enforcing a unique-target
// capacity. It fails instead of silently weakening exact deduplication when the capacity is full.
type DeduplicatingSource struct {
	source      Source
	maxUnique   int
	seen        map[string]struct{}
	terminalErr error
	closed      bool
}

// NewDeduplicatingSource wraps a source with bounded, exact duplicate suppression.
func NewDeduplicatingSource(source Source, maxUnique int) (*DeduplicatingSource, error) {
	if source == nil {
		return nil, newSourceError("create deduplicating source: source is nil", nil)
	}
	if maxUnique <= 0 {
		return nil, newSourceError(
			"create deduplicating source: unique target limit must be positive",
			nil,
		)
	}

	return &DeduplicatingSource{
		source:    source,
		maxUnique: maxUnique,
		seen:      make(map[string]struct{}, min(maxUnique, 1024)),
	}, nil
}

// Next returns the next previously unseen canonical target.
func (source *DeduplicatingSource) Next(ctx context.Context) (model.Target, error) {
	if err := ctx.Err(); err != nil {
		return model.Target{}, err
	}
	if source.closed {
		return model.Target{}, io.EOF
	}
	if source.terminalErr != nil {
		return model.Target{}, source.terminalErr
	}

	for {
		target, err := source.source.Next(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				source.terminalErr = err
			}
			return model.Target{}, err
		}

		key := target.String()
		if _, exists := source.seen[key]; exists {
			continue
		}
		if len(source.seen) >= source.maxUnique {
			source.terminalErr = newSourceError(
				"deduplicate targets: unique target limit reached",
				ErrDeduplicationLimit,
			)
			return model.Target{}, source.terminalErr
		}

		source.seen[key] = struct{}{}
		return target, nil
	}
}

// Close releases the wrapped source and the deduplication set. It is safe to call more than once.
func (source *DeduplicatingSource) Close() error {
	if source.closed {
		return nil
	}
	source.closed = true
	source.terminalErr = io.EOF
	source.seen = nil
	wrapped := source.source
	source.source = nil
	if err := wrapped.Close(); err != nil {
		return newSourceError("close deduplicating source: close wrapped source", err)
	}
	return nil
}
