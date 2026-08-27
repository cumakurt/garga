package target

import (
	"context"
	"errors"
	"io"

	"github.com/cumakurt/garga/internal/model"
)

// Chain concatenates sources in order. Empty and nil sources are rejected.
// Close closes any source that has not already been exhausted.
func Chain(sources ...Source) (Source, error) {
	if len(sources) == 0 {
		return nil, newSourceError("create chained target source: at least one source is required", nil)
	}
	cloned := make([]Source, 0, len(sources))
	for _, source := range sources {
		if source == nil {
			return nil, newSourceError("create chained target source: source is nil", nil)
		}
		cloned = append(cloned, source)
	}
	if len(cloned) == 1 {
		return cloned[0], nil
	}
	return &chainSource{sources: cloned}, nil
}

type chainSource struct {
	sources []Source
	index   int
	closed  bool
}

func (source *chainSource) Next(ctx context.Context) (model.Target, error) {
	if err := ctx.Err(); err != nil {
		return model.Target{}, err
	}
	if source.closed {
		return model.Target{}, io.EOF
	}

	for source.index < len(source.sources) {
		next, err := source.sources[source.index].Next(ctx)
		if err == nil {
			return next, nil
		}
		if !errors.Is(err, io.EOF) {
			return model.Target{}, err
		}
		if closeErr := source.sources[source.index].Close(); closeErr != nil {
			source.index++
			return model.Target{}, closeErr
		}
		source.index++
	}
	return model.Target{}, io.EOF
}

func (source *chainSource) Close() error {
	if source.closed {
		return nil
	}
	source.closed = true

	var first error
	for index := source.index; index < len(source.sources); index++ {
		if err := source.sources[index].Close(); err != nil && first == nil {
			first = err
		}
	}
	source.sources = nil
	return first
}
