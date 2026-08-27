package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cumakurt/garga/internal/logging"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/probe"
	"github.com/cumakurt/garga/internal/ratelimit"
)

type requestLimiter interface {
	Wait(ctx context.Context, host string) error
}

// Engine runs one bounded endpoint stream through a shared prober.
type Engine struct {
	options Options
	prober  probe.Prober
	limiter requestLimiter
	sleep   func(context.Context, time.Duration) error
}

type task struct {
	sequence uint64
	endpoint model.Endpoint
}

type runCounters struct {
	submitted         atomic.Uint64
	started           atomic.Uint64
	attempts          atomic.Uint64
	retries           atomic.Uint64
	completed         atomic.Uint64
	succeeded         atomic.Uint64
	failed            atomic.Uint64
	emitted           atomic.Uint64
	activeWorkers     atomic.Uint64
	peakQueue         atomic.Uint64
	peakActiveWorkers atomic.Uint64
	peakReorder       atomic.Uint64
}

// New creates an engine whose goroutine, queue, rate, and retry limits are immutable.
func New(options Options, prober probe.Prober) (*Engine, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	if prober == nil {
		return nil, errors.New("create scanner engine: prober is required")
	}
	limiter, err := ratelimit.New(options.GlobalRate, options.PerHostRate)
	if err != nil {
		return nil, err
	}
	return &Engine{
		options: options,
		prober:  prober,
		limiter: limiter,
		sleep:   sleepContext,
	}, nil
}

// Run owns and closes source and sink, returning after every worker and output operation stops.
func (engine *Engine) Run(parent context.Context, source Source, sink Sink) (Stats, error) {
	if engine == nil || engine.prober == nil {
		return Stats{}, errors.New("run scanner: engine is not initialized")
	}
	if parent == nil {
		return Stats{}, errors.New("run scanner: context is required")
	}
	if source == nil {
		return Stats{}, errors.New("run scanner: source is required")
	}
	if sink == nil {
		return Stats{}, errors.New("run scanner: sink is required")
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	counters := &runCounters{}
	jobs := make(chan task, engine.options.QueueCapacity)
	results := make(chan Result, engine.options.Workers)
	outstandingWindow := engine.options.QueueCapacity + engine.options.Workers
	window := make(chan struct{}, outstandingWindow)
	producerError := make(chan error, 1)

	engine.logger().Info(
		"scanner started",
		slog.Int("workers", engine.options.Workers),
		slog.Int("queue_capacity", engine.options.QueueCapacity),
	)

	go engine.produce(ctx, cancel, source, jobs, window, counters, producerError)

	stopProgress := engine.watchProgress(counters, engine.options.QueueCapacity, outstandingWindow)
	defer stopProgress()

	var workers sync.WaitGroup
	workers.Add(engine.options.Workers)
	for range engine.options.Workers {
		go func() {
			defer workers.Done()
			engine.work(ctx, jobs, results, counters)
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()

	sinkErr := engine.consume(parent, cancel, sink, results, window, counters)
	sourceErr := <-producerError
	closeErr := sink.Close()
	stats := counters.snapshot(engine.options.QueueCapacity, outstandingWindow)
	engine.logger().Info("scanner finished", stats.logAttrs()...)

	switch {
	case sinkErr != nil:
		return stats, fmt.Errorf("write scanner result: %w", sinkErr)
	case sourceErr != nil && !errors.Is(sourceErr, context.Canceled):
		return stats, fmt.Errorf("read scanner source: %w", sourceErr)
	case closeErr != nil:
		return stats, fmt.Errorf("close scanner sink: %w", closeErr)
	case parent.Err() != nil:
		return stats, parent.Err()
	case sourceErr != nil:
		return stats, sourceErr
	default:
		return stats, nil
	}
}

func (engine *Engine) produce(
	ctx context.Context,
	cancel context.CancelFunc,
	source Source,
	jobs chan<- task,
	window chan struct{},
	counters *runCounters,
	producerError chan<- error,
) {
	defer close(jobs)
	var resultErr error
	defer func() {
		if closeErr := source.Close(); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
		producerError <- resultErr
	}()

	var sequence uint64
	for {
		select {
		case window <- struct{}{}:
		case <-ctx.Done():
			resultErr = ctx.Err()
			return
		}

		endpoint, err := source.Next(ctx)
		if err != nil {
			<-window
			if errors.Is(err, io.EOF) {
				return
			}
			resultErr = err
			cancel()
			return
		}

		work := task{sequence: sequence, endpoint: endpoint}
		select {
		case jobs <- work:
			sequence++
			counters.submitted.Add(1)
			updatePeak(&counters.peakQueue, uint64(len(jobs)))
		case <-ctx.Done():
			<-window
			resultErr = ctx.Err()
			return
		}
	}
}

func (engine *Engine) work(ctx context.Context, jobs <-chan task, results chan<- Result, counters *runCounters) {
	for {
		select {
		case <-ctx.Done():
			return
		case work, ok := <-jobs:
			if !ok {
				return
			}
			active := counters.activeWorkers.Add(1)
			updatePeak(&counters.peakActiveWorkers, active)
			result, completed := engine.execute(ctx, work, counters)
			counters.activeWorkers.Add(^uint64(0))
			if !completed {
				continue
			}
			counters.completed.Add(1)
			if result.Error == nil {
				counters.succeeded.Add(1)
			} else {
				counters.failed.Add(1)
			}
			results <- result
		}
	}
}

func (engine *Engine) execute(ctx context.Context, work task, counters *runCounters) (Result, bool) {
	result := Result{Sequence: work.sequence, Endpoint: work.endpoint}
	for attempt := 1; attempt <= engine.options.Retries+1; attempt++ {
		if err := engine.limiter.Wait(ctx, work.endpoint.Host); err != nil {
			return Result{}, false
		}
		if attempt == 1 {
			counters.started.Add(1)
		}
		counters.attempts.Add(1)
		result.Attempts = attempt
		engine.logger().Debug(
			"scanner probe attempt",
			slog.Uint64("sequence", work.sequence),
			slog.Int("attempt", attempt),
		)
		result.Probe, result.Error = engine.prober.Probe(ctx, work.endpoint)
		if result.Error != nil {
			kind, ok := probe.KindOf(result.Error)
			if !ok {
				kind = "other"
			}
			engine.logger().Debug(
				"scanner probe error",
				slog.Uint64("sequence", work.sequence),
				logging.Bounded("error_kind", string(kind), probeErrorKinds...),
			)
		}
		if ctx.Err() != nil && (errors.Is(result.Error, context.Canceled) || errors.Is(result.Error, context.DeadlineExceeded)) {
			return Result{}, false
		}
		if attempt > engine.options.Retries || !shouldRetry(result.Probe, result.Error) {
			return result, true
		}

		counters.retries.Add(1)
		if err := engine.sleep(ctx, retryDelay(engine.options, work.endpoint, attempt)); err != nil {
			return Result{}, false
		}
	}
	return result, true
}

func (engine *Engine) consume(
	parent context.Context,
	cancel context.CancelFunc,
	sink Sink,
	results <-chan Result,
	window chan struct{},
	counters *runCounters,
) error {
	pending := make(map[uint64]Result, cap(window))
	var next uint64
	var sinkErr error
	sinkContext := context.WithoutCancel(parent)

	for result := range results {
		if sinkErr != nil {
			<-window
			continue
		}
		pending[result.Sequence] = result
		updatePeak(&counters.peakReorder, uint64(len(pending)))
		for {
			ordered, exists := pending[next]
			if !exists {
				break
			}
			delete(pending, next)
			if err := sink.Write(sinkContext, ordered); err != nil {
				<-window
				sinkErr = err
				cancel()
				break
			}
			<-window
			counters.emitted.Add(1)
			next++
		}
	}

	sequences := make([]uint64, 0, len(pending))
	for sequence := range pending {
		sequences = append(sequences, sequence)
	}
	sort.Slice(sequences, func(left, right int) bool { return sequences[left] < sequences[right] })
	for _, sequence := range sequences {
		<-window
		if sinkErr != nil {
			continue
		}
		if err := sink.Write(sinkContext, pending[sequence]); err != nil {
			sinkErr = err
			cancel()
			continue
		}
		counters.emitted.Add(1)
	}
	return sinkErr
}

func (counters *runCounters) snapshot(queueCapacity, outstandingWindow int) Stats {
	return Stats{
		Submitted:         counters.submitted.Load(),
		Started:           counters.started.Load(),
		Attempts:          counters.attempts.Load(),
		Retries:           counters.retries.Load(),
		Completed:         counters.completed.Load(),
		Succeeded:         counters.succeeded.Load(),
		Failed:            counters.failed.Load(),
		Emitted:           counters.emitted.Load(),
		PeakQueueDepth:    counters.peakQueue.Load(),
		PeakActiveWorkers: counters.peakActiveWorkers.Load(),
		PeakReorderBuffer: counters.peakReorder.Load(),
		QueueCapacity:     queueCapacity,
		OutstandingWindow: outstandingWindow,
	}
}

func (engine *Engine) logger() *slog.Logger {
	if engine.options.Logger != nil {
		return engine.options.Logger
	}
	return slog.New(slog.DiscardHandler)
}

func (engine *Engine) watchProgress(counters *runCounters, queueCapacity, outstandingWindow int) func() {
	if engine.options.Progress == nil {
		return func() {}
	}
	stop := make(chan struct{})
	var done sync.WaitGroup
	done.Add(1)
	report := func() {
		engine.options.Progress(counters.snapshot(queueCapacity, outstandingWindow))
	}
	go func() {
		defer done.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		report()
		for {
			select {
			case <-stop:
				report()
				return
			case <-ticker.C:
				report()
			}
		}
	}()
	return func() {
		close(stop)
		done.Wait()
	}
}

var probeErrorKinds = []string{
	string(probe.ErrorInvalidEndpoint),
	string(probe.ErrorCanceled),
	string(probe.ErrorTimeout),
	string(probe.ErrorTCP),
	string(probe.ErrorTLS),
	string(probe.ErrorHTTP),
}

func updatePeak(peak *atomic.Uint64, value uint64) {
	for current := peak.Load(); value > current; current = peak.Load() {
		if peak.CompareAndSwap(current, value) {
			return
		}
	}
}
