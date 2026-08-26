package scanner

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/probe"
)

func assertEngineLoadRemainsBounded(t *testing.T, taskCount uint64) {
	t.Helper()
	options := scannerTestOptions(t)
	options.Workers = 8
	options.QueueCapacity = 16
	options.Retries = 0

	baselineGoroutines := runtime.NumGoroutine()
	var peakGoroutines atomic.Uint64
	prober := probeFunc(func(_ context.Context, _ model.Endpoint) (probe.Result, error) {
		updatePeak(&peakGoroutines, uint64(runtime.NumGoroutine()))
		return probe.Result{StatusCode: 200}, nil
	})
	engine := newScannerTestEngine(t, options, prober)
	source := &generatedSource{total: taskCount}
	sink := &recordingSink{}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	stats, err := engine.Run(context.Background(), source, sink)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if stats.Submitted != taskCount || stats.Started != taskCount || stats.Completed != taskCount || stats.Emitted != taskCount {
		t.Fatalf("task stats = %#v", stats)
	}
	if stats.Attempts != taskCount || stats.Retries != 0 || stats.Succeeded != taskCount || stats.Failed != 0 {
		t.Fatalf("attempt stats = %#v", stats)
	}
	if stats.PeakQueueDepth > uint64(options.QueueCapacity) {
		t.Fatalf("peak queue = %d, capacity %d", stats.PeakQueueDepth, options.QueueCapacity)
	}
	if stats.PeakActiveWorkers > uint64(options.Workers) {
		t.Fatalf("peak workers = %d, limit %d", stats.PeakActiveWorkers, options.Workers)
	}
	if stats.PeakReorderBuffer > uint64(stats.OutstandingWindow) {
		t.Fatalf("peak reorder buffer = %d, window %d", stats.PeakReorderBuffer, stats.OutstandingWindow)
	}
	if stats.OutstandingWindow != options.Workers+options.QueueCapacity {
		t.Fatalf("outstanding window = %d", stats.OutstandingWindow)
	}
	if sink.Count() != taskCount || !sink.IsStrictlyOrderedFromZero() {
		t.Fatalf("sink count/order = %d, %t", sink.Count(), sink.IsStrictlyOrderedFromZero())
	}
	if sink.storedCount() != 0 {
		t.Fatalf("sink retained %d results; counting sink must not accumulate findings", sink.storedCount())
	}
	if source.closeCalls.Load() != 1 || sink.closeCalls.Load() != 1 {
		t.Fatalf("close calls = source %d, sink %d", source.closeCalls.Load(), sink.closeCalls.Load())
	}
	if got, limit := peakGoroutines.Load(), uint64(baselineGoroutines+options.Workers+16); got > limit {
		t.Fatalf("peak goroutines = %d, expected at most %d", got, limit)
	}

	throughput := float64(taskCount) / elapsed.Seconds()
	t.Logf(
		"tasks=%d elapsed=%s throughput=%.0f/s peak_goroutines=%d peak_queue=%d peak_workers=%d peak_reorder=%d heap_inuse_before=%d heap_inuse_after=%d",
		taskCount,
		elapsed,
		throughput,
		peakGoroutines.Load(),
		stats.PeakQueueDepth,
		stats.PeakActiveWorkers,
		stats.PeakReorderBuffer,
		before.HeapInuse,
		after.HeapInuse,
	)
}

func TestEngineSequentialTaskLatencyPercentiles(t *testing.T) {
	const taskCount = 10_000
	options := scannerTestOptions(t)
	options.Workers = 1
	options.QueueCapacity = 1
	options.Retries = 0

	latencies := make([]time.Duration, 0, taskCount)
	var lastEmit time.Time
	sink := &recordingSink{onWrite: func(Result) {
		now := time.Now()
		if !lastEmit.IsZero() {
			latencies = append(latencies, now.Sub(lastEmit))
		}
		lastEmit = now
	}}
	engine := newScannerTestEngine(t, options, successfulProber())
	started := time.Now()
	stats, err := engine.Run(context.Background(), &generatedSource{total: taskCount}, sink)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if stats.Emitted != taskCount {
		t.Fatalf("emitted = %d, want %d", stats.Emitted, taskCount)
	}
	t.Logf("elapsed=%s mean_task=%s emit_interval p50=%s p95=%s p99=%s samples=%d",
		elapsed,
		elapsed/taskCount,
		durationPercentile(latencies, 50),
		durationPercentile(latencies, 95),
		durationPercentile(latencies, 99),
		len(latencies),
	)
}

func (sink *recordingSink) storedCount() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return len(sink.results)
}

func durationPercentile(samples []time.Duration, percentile int) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	index := (percentile*len(sorted) + 99) / 100
	if index < 1 {
		index = 1
	}
	if index > len(sorted) {
		index = len(sorted)
	}
	return sorted[index-1]
}

func BenchmarkEngineInMemoryProber(b *testing.B) {
	for _, taskCount := range []uint64{1_000, 10_000} {
		b.Run(fmt.Sprintf("tasks/%d", taskCount), func(b *testing.B) {
			options := scannerTestOptions(b)
			options.Workers = 8
			options.QueueCapacity = 16
			options.Retries = 0
			prober := probeFunc(func(context.Context, model.Endpoint) (probe.Result, error) {
				return probe.Result{StatusCode: 200}, nil
			})
			engine := newScannerTestEngine(b, options, prober)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				source := &generatedSource{total: taskCount}
				sink := &recordingSink{}
				b.StartTimer()
				stats, err := engine.Run(context.Background(), source, sink)
				if err != nil {
					b.Fatalf("Run() error = %v", err)
				}
				if stats.Emitted != taskCount {
					b.Fatalf("emitted = %d, want %d", stats.Emitted, taskCount)
				}
			}
		})
	}
}
