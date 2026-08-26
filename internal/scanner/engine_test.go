package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/probe"
)

func TestEngineSyntheticLoadsRemainBounded(t *testing.T) {
	for _, taskCount := range []uint64{1_000, 10_000, 100_000} {
		t.Run(fmt.Sprintf("tasks/%d", taskCount), func(t *testing.T) {
			if taskCount >= 100_000 && testing.Short() {
				t.Skip("skipping 100k synthetic load in short mode")
			}
			assertEngineLoadRemainsBounded(t, taskCount)
		})
	}
}

func TestEngineEmitsInputOrderWithBoundedReordering(t *testing.T) {
	const taskCount = 12
	options := scannerTestOptions(t)
	options.Workers = 4
	options.QueueCapacity = 4
	options.Retries = 0

	releaseFirst := make(chan struct{})
	var started atomic.Uint64
	var releaseOnce sync.Once
	prober := probeFunc(func(_ context.Context, endpoint model.Endpoint) (probe.Result, error) {
		current := started.Add(1)
		if current >= uint64(options.Workers) {
			releaseOnce.Do(func() { close(releaseFirst) })
		}
		if endpoint.Path == "/0" {
			<-releaseFirst
		}
		return probe.Result{StatusCode: 200, Body: []byte(endpoint.Path)}, nil
	})
	engine := newScannerTestEngine(t, options, prober)
	sink := &recordingSink{store: true}
	stats, err := engine.Run(context.Background(), &generatedSource{total: taskCount}, sink)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !sink.IsStrictlyOrderedFromZero() {
		t.Fatalf("sequences = %v", sink.Sequences())
	}
	if stats.PeakReorderBuffer > uint64(options.Workers+options.QueueCapacity) {
		t.Fatalf("peak reorder buffer = %d", stats.PeakReorderBuffer)
	}
}

func TestEngineCancellationStopsProducerRequestsAndClosesOutput(t *testing.T) {
	options := scannerTestOptions(t)
	options.Workers = 4
	options.QueueCapacity = 4
	options.Retries = 0

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prober := probeFunc(func(ctx context.Context, endpoint model.Endpoint) (probe.Result, error) {
		if endpoint.Path == "/0" {
			return probe.Result{StatusCode: 200}, nil
		}
		<-ctx.Done()
		return probe.Result{}, ctx.Err()
	})
	engine := newScannerTestEngine(t, options, prober)
	source := &generatedSource{infinite: true}
	sink := &recordingSink{onWrite: func(Result) { cancel() }}

	stats, err := engine.Run(ctx, source, sink)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if stats.Emitted != 1 || sink.Count() != 1 {
		t.Fatalf("completed output = stats %d, sink %d", stats.Emitted, sink.Count())
	}
	if stats.Submitted > uint64(stats.OutstandingWindow+1) {
		t.Fatalf("submitted %d tasks after cancellation with window %d", stats.Submitted, stats.OutstandingWindow)
	}
	if source.closeCalls.Load() != 1 || sink.closeCalls.Load() != 1 {
		t.Fatalf("close calls = source %d, sink %d", source.closeCalls.Load(), sink.closeCalls.Load())
	}
}

func TestEngineDrainsCompletedResultsAcrossCancellationGap(t *testing.T) {
	options := scannerTestOptions(t)
	options.Workers = 2
	options.QueueCapacity = 2
	options.Retries = 0

	ctx, cancel := context.WithCancel(context.Background())
	firstStarted := make(chan struct{})
	secondCompleted := make(chan struct{})
	var firstOnce sync.Once
	var secondOnce sync.Once
	prober := probeFunc(func(ctx context.Context, endpoint model.Endpoint) (probe.Result, error) {
		switch endpoint.Path {
		case "/0":
			firstOnce.Do(func() { close(firstStarted) })
			<-ctx.Done()
			return probe.Result{}, ctx.Err()
		case "/1":
			secondOnce.Do(func() { close(secondCompleted) })
			return probe.Result{StatusCode: 200}, nil
		default:
			return probe.Result{}, errors.New("unexpected endpoint")
		}
	})
	engine := newScannerTestEngine(t, options, prober)
	sink := &recordingSink{store: true}

	type runOutcome struct {
		stats Stats
		err   error
	}
	outcome := make(chan runOutcome, 1)
	go func() {
		stats, err := engine.Run(ctx, &generatedSource{total: 2}, sink)
		outcome <- runOutcome{stats: stats, err: err}
	}()
	<-firstStarted
	<-secondCompleted
	cancel()

	result := <-outcome
	if !errors.Is(result.err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", result.err)
	}
	if result.stats.Completed != 1 || result.stats.Emitted != 1 {
		t.Fatalf("stats = %#v", result.stats)
	}
	if got := sink.Sequences(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("drained sequences = %v, want [1]", got)
	}
}

func TestEngineRetryPolicy(t *testing.T) {
	tests := []struct {
		name         string
		outcomes     []probeOutcome
		wantAttempts int
		wantRetries  uint64
		wantError    bool
	}{
		{
			name: "transient timeout succeeds",
			outcomes: []probeOutcome{
				{err: context.DeadlineExceeded},
				{err: context.DeadlineExceeded},
				{result: probe.Result{StatusCode: 200}},
			},
			wantAttempts: 3,
			wantRetries:  2,
		},
		{
			name: "server error succeeds",
			outcomes: []probeOutcome{
				{result: probe.Result{StatusCode: 503}},
				{result: probe.Result{StatusCode: 200}},
			},
			wantAttempts: 2,
			wantRetries:  1,
		},
		{
			name:         "authentication is permanent",
			outcomes:     []probeOutcome{{result: probe.Result{StatusCode: 401}}},
			wantAttempts: 1,
		},
		{
			name:         "authorization is permanent",
			outcomes:     []probeOutcome{{result: probe.Result{StatusCode: 403}}},
			wantAttempts: 1,
		},
		{
			name:         "parse failure is permanent",
			outcomes:     []probeOutcome{{err: errors.New("deterministic parse failure")}},
			wantAttempts: 1,
			wantError:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := scannerTestOptions(t)
			options.Workers = 1
			options.QueueCapacity = 1
			options.Retries = 2
			var call atomic.Uint64
			prober := probeFunc(func(context.Context, model.Endpoint) (probe.Result, error) {
				index := int(call.Add(1)) - 1
				if index >= len(test.outcomes) {
					t.Fatalf("unexpected probe call %d", index+1)
				}
				return test.outcomes[index].result, test.outcomes[index].err
			})
			engine := newScannerTestEngine(t, options, prober)
			limiter := &recordingLimiter{}
			engine.limiter = limiter
			var delays []time.Duration
			engine.sleep = func(ctx context.Context, delay time.Duration) error {
				delays = append(delays, delay)
				return ctx.Err()
			}
			sink := &recordingSink{store: true}
			stats, err := engine.Run(context.Background(), &generatedSource{total: 1}, sink)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			results := sink.Results()
			if len(results) != 1 {
				t.Fatalf("results = %d, want 1", len(results))
			}
			if results[0].Attempts != test.wantAttempts || int(call.Load()) != test.wantAttempts {
				t.Fatalf("attempts = result %d, calls %d; want %d", results[0].Attempts, call.Load(), test.wantAttempts)
			}
			if (results[0].Error != nil) != test.wantError {
				t.Fatalf("result error = %v, wantError %t", results[0].Error, test.wantError)
			}
			if stats.Retries != test.wantRetries || len(delays) != int(test.wantRetries) {
				t.Fatalf("retries = stats %d, delays %d; want %d", stats.Retries, len(delays), test.wantRetries)
			}
			if limiter.calls.Load() != uint64(test.wantAttempts) {
				t.Fatalf("limiter calls = %d, want %d", limiter.calls.Load(), test.wantAttempts)
			}
		})
	}
}

func TestEngineDoesNotRetrySourceFailure(t *testing.T) {
	t.Parallel()

	sourceErr := errors.New("deterministic source parse failure")
	source := &generatedSource{nextErr: sourceErr}
	var calls atomic.Uint64
	engine := newScannerTestEngine(t, scannerTestOptions(t), probeFunc(func(context.Context, model.Endpoint) (probe.Result, error) {
		calls.Add(1)
		return probe.Result{}, nil
	}))
	sink := &recordingSink{}
	stats, err := engine.Run(context.Background(), source, sink)
	if !errors.Is(err, sourceErr) {
		t.Fatalf("Run() error = %v, want source error", err)
	}
	if calls.Load() != 0 || stats.Attempts != 0 || stats.Retries != 0 {
		t.Fatalf("calls/stats = %d, %#v", calls.Load(), stats)
	}
	if source.closeCalls.Load() != 1 || sink.closeCalls.Load() != 1 {
		t.Fatal("source and sink were not closed")
	}
}

func TestEnginePropagatesSinkAndCloseErrors(t *testing.T) {
	t.Parallel()

	t.Run("write error", func(t *testing.T) {
		writeErr := errors.New("write failure")
		sink := &recordingSink{writeErr: writeErr}
		engine := newScannerTestEngine(t, scannerTestOptions(t), successfulProber())
		_, err := engine.Run(context.Background(), &generatedSource{total: 1}, sink)
		if !errors.Is(err, writeErr) {
			t.Fatalf("Run() error = %v, want write error", err)
		}
		if sink.closeCalls.Load() != 1 {
			t.Fatal("sink was not closed after write failure")
		}
	})

	t.Run("sink close error", func(t *testing.T) {
		closeErr := errors.New("sink close failure")
		sink := &recordingSink{closeErr: closeErr}
		engine := newScannerTestEngine(t, scannerTestOptions(t), successfulProber())
		_, err := engine.Run(context.Background(), &generatedSource{}, sink)
		if !errors.Is(err, closeErr) {
			t.Fatalf("Run() error = %v, want sink close error", err)
		}
	})

	t.Run("source close error", func(t *testing.T) {
		closeErr := errors.New("source close failure")
		source := &generatedSource{closeErr: closeErr}
		engine := newScannerTestEngine(t, scannerTestOptions(t), successfulProber())
		_, err := engine.Run(context.Background(), source, &recordingSink{})
		if !errors.Is(err, closeErr) {
			t.Fatalf("Run() error = %v, want source close error", err)
		}
	})
}

func TestEngineValidation(t *testing.T) {
	t.Parallel()

	options := scannerTestOptions(t)
	if _, err := New(options, nil); err == nil {
		t.Fatal("New() accepted nil prober")
	}
	options.Workers = 0
	if _, err := New(options, successfulProber()); err == nil {
		t.Fatal("New() accepted invalid options")
	}

	var nilEngine *Engine
	if _, err := nilEngine.Run(context.Background(), &generatedSource{}, &recordingSink{}); err == nil {
		t.Fatal("nil Engine.Run() returned nil error")
	}
	engine := newScannerTestEngine(t, scannerTestOptions(t), successfulProber())
	if _, err := engine.Run(nil, &generatedSource{}, &recordingSink{}); err == nil {
		t.Fatal("Run() accepted nil context")
	}
	if _, err := engine.Run(context.Background(), nil, &recordingSink{}); err == nil {
		t.Fatal("Run() accepted nil source")
	}
	if _, err := engine.Run(context.Background(), &generatedSource{}, nil); err == nil {
		t.Fatal("Run() accepted nil sink")
	}
}

type probeOutcome struct {
	result probe.Result
	err    error
}

type probeFunc func(context.Context, model.Endpoint) (probe.Result, error)

func (function probeFunc) Probe(ctx context.Context, endpoint model.Endpoint) (probe.Result, error) {
	return function(ctx, endpoint)
}

type generatedSource struct {
	total      uint64
	current    uint64
	infinite   bool
	nextErr    error
	closeErr   error
	closeCalls atomic.Uint64
}

func (source *generatedSource) Next(ctx context.Context) (model.Endpoint, error) {
	select {
	case <-ctx.Done():
		return model.Endpoint{}, ctx.Err()
	default:
	}
	if source.nextErr != nil {
		return model.Endpoint{}, source.nextErr
	}
	if !source.infinite && source.current >= source.total {
		return model.Endpoint{}, io.EOF
	}
	sequence := source.current
	source.current++
	return model.Endpoint{
		Scheme: model.SchemeHTTP,
		Host:   fmt.Sprintf("host-%d.example", sequence%100),
		Port:   9200,
		Path:   fmt.Sprintf("/%d", sequence),
	}, nil
}

func (source *generatedSource) Close() error {
	source.closeCalls.Add(1)
	return source.closeErr
}

type recordingSink struct {
	mu         sync.Mutex
	count      uint64
	last       uint64
	hasLast    bool
	ordered    bool
	store      bool
	results    []Result
	onWrite    func(Result)
	writeErr   error
	closeErr   error
	closeCalls atomic.Uint64
}

func (sink *recordingSink) Write(_ context.Context, result Result) error {
	if sink.writeErr != nil {
		return sink.writeErr
	}
	sink.mu.Lock()
	if !sink.hasLast {
		sink.ordered = result.Sequence == 0
		sink.hasLast = true
	} else if result.Sequence != sink.last+1 {
		sink.ordered = false
	}
	sink.last = result.Sequence
	sink.count++
	if sink.store {
		sink.results = append(sink.results, result)
	}
	callback := sink.onWrite
	sink.mu.Unlock()
	if callback != nil {
		callback(result)
	}
	return nil
}

func (sink *recordingSink) Close() error {
	sink.closeCalls.Add(1)
	return sink.closeErr
}

func (sink *recordingSink) Count() uint64 {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.count
}

func (sink *recordingSink) IsStrictlyOrderedFromZero() bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.ordered
}

func (sink *recordingSink) Sequences() []uint64 {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sequences := make([]uint64, len(sink.results))
	for index, result := range sink.results {
		sequences[index] = result.Sequence
	}
	return sequences
}

func (sink *recordingSink) Results() []Result {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]Result(nil), sink.results...)
}

type recordingLimiter struct {
	calls atomic.Uint64
}

func (limiter *recordingLimiter) Wait(ctx context.Context, _ string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		limiter.calls.Add(1)
		return nil
	}
}

func scannerTestOptions(t testing.TB) Options {
	t.Helper()
	options, err := OptionsFromConfig(config.Defaults())
	if err != nil {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
	return options
}

func newScannerTestEngine(t testing.TB, options Options, prober probe.Prober) *Engine {
	t.Helper()
	engine, err := New(options, prober)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	engine.limiter = &recordingLimiter{}
	engine.sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	return engine
}

func successfulProber() probe.Prober {
	return probeFunc(func(context.Context, model.Endpoint) (probe.Result, error) {
		return probe.Result{StatusCode: 200}, nil
	})
}
