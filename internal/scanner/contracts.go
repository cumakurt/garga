package scanner

import (
	"context"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/probe"
)

// Source streams concrete endpoints and releases any owned resource on Close.
type Source interface {
	Next(ctx context.Context) (model.Endpoint, error)
	Close() error
}

// Sink consumes ordered results and finalizes its output on Close.
type Sink interface {
	Write(ctx context.Context, result Result) error
	Close() error
}

// SinkFunc adapts a function to a Sink with a no-op Close.
type SinkFunc func(ctx context.Context, result Result) error

func (function SinkFunc) Write(ctx context.Context, result Result) error {
	return function(ctx, result)
}

func (function SinkFunc) Close() error {
	return nil
}

// Result associates one endpoint with its deterministic input sequence and probe outcome.
type Result struct {
	Sequence uint64
	Endpoint model.Endpoint
	Probe    probe.Result
	Attempts int
	Error    error
}

// Stats is a bounded-cardinality summary of one engine run.
type Stats struct {
	Submitted         uint64
	Started           uint64
	Attempts          uint64
	Retries           uint64
	Completed         uint64
	Succeeded         uint64
	Failed            uint64
	Emitted           uint64
	PeakQueueDepth    uint64
	PeakActiveWorkers uint64
	PeakReorderBuffer uint64
	QueueCapacity     int
	OutstandingWindow int
}
