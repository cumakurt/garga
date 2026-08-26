package target

import (
	"context"
	"io"
	"sort"
	"testing"
	"time"
)

func BenchmarkParseIPv4(b *testing.B) {
	benchmarkParse(b, "192.0.2.10")
}

func BenchmarkParseHostname(b *testing.B) {
	benchmarkParse(b, "es-prod.example.internal")
}

func BenchmarkParseURL(b *testing.B) {
	benchmarkParse(b, "https://192.0.2.10:9200/_cluster/health")
}

func benchmarkParse(b *testing.B, raw string) {
	b.Helper()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Parse(raw, "bench"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCIDRSourceNext(b *testing.B) {
	ctx := context.Background()
	source, err := NewCIDRSource("10.0.0.0/8", "bench")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, err := source.Next(ctx)
		if err != io.EOF {
			if err != nil {
				b.Fatal(err)
			}
			continue
		}
		replaced, createErr := NewCIDRSource("10.0.0.0/8", "bench")
		if createErr != nil {
			b.Fatal(createErr)
		}
		_ = source.Close()
		source = replaced
		if _, err := source.Next(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func TestParseLatencyPercentiles(t *testing.T) {
	const samples = 10_000
	inputs := []string{
		"192.0.2.10",
		"es-prod.example.internal",
		"https://192.0.2.10:9200/_cluster/health",
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			for range 1_000 {
				if _, err := Parse(input, "bench"); err != nil {
					t.Fatal(err)
				}
			}
			durations := make([]time.Duration, samples)
			for index := range durations {
				started := time.Now()
				if _, err := Parse(input, "bench"); err != nil {
					t.Fatal(err)
				}
				durations[index] = time.Since(started)
			}
			t.Logf("p50=%s p95=%s p99=%s",
				durationPercentile(durations, 50),
				durationPercentile(durations, 95),
				durationPercentile(durations, 99),
			)
		})
	}
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
