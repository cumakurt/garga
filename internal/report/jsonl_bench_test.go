package report

import (
	"context"
	"fmt"
	"io"
	"sort"
	"testing"
	"time"
)

func BenchmarkJSONLWrite(b *testing.B) {
	finding := sampleFindings()[0]
	writer, err := New(FormatJSONL, io.Discard)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = writer.Close() })
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := writer.Write(context.Background(), finding); err != nil {
			b.Fatal(err)
		}
	}
}

func TestJSONLStreamingLoadsDoNotRetainFindings(t *testing.T) {
	finding := sampleFindings()[0]
	for _, count := range []int{1_000, 10_000, 100_000} {
		t.Run(fmt.Sprintf("%d", count), func(t *testing.T) {
			if count >= 100_000 && testing.Short() {
				t.Skip("skipping 100k JSONL stream in short mode")
			}
			writer, err := New(FormatJSONL, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			assertNoFindingSlice(t, writer)
			started := time.Now()
			for range count {
				if writeErr := writer.Write(context.Background(), finding); writeErr != nil {
					t.Fatal(writeErr)
				}
			}
			elapsed := time.Since(started)
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			assertNoFindingSlice(t, writer)
			t.Logf("count=%d elapsed=%s throughput=%.0f/s", count, elapsed, float64(count)/elapsed.Seconds())
		})
	}
}

func TestJSONLWriteLatencyPercentiles(t *testing.T) {
	writer, err := New(FormatJSONL, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	finding := sampleFindings()[0]
	for range 1_000 {
		if writeErr := writer.Write(context.Background(), finding); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	const samples = 10_000
	durations := make([]time.Duration, samples)
	for index := range durations {
		started := time.Now()
		if writeErr := writer.Write(context.Background(), finding); writeErr != nil {
			t.Fatal(writeErr)
		}
		durations[index] = time.Since(started)
	}
	t.Logf("p50=%s p95=%s p99=%s",
		durationPercentile(durations, 50),
		durationPercentile(durations, 95),
		durationPercentile(durations, 99),
	)
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
