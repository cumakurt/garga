package fingerprint

import (
	"os"
	"sort"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/probe"
)

func BenchmarkAnalyzeElasticsearchRoot(b *testing.B) {
	body, err := os.ReadFile("testdata/elasticsearch-9.4.4.json")
	if err != nil {
		b.Fatal(err)
	}
	options, err := OptionsFromConfig(config.Defaults())
	if err != nil {
		b.Fatal(err)
	}
	engine, err := New(options)
	if err != nil {
		b.Fatal(err)
	}
	response := elasticResponse(body, true)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		result := engine.Analyze(response)
		if !result.Detected || result.Product != productElasticsearch {
			b.Fatalf("result = %#v", result)
		}
	}
}

func BenchmarkAnalyzeNegativeHTML(b *testing.B) {
	body, err := os.ReadFile("testdata/nginx.html")
	if err != nil {
		b.Fatal(err)
	}
	engine, err := New(Options{Threshold: config.DefaultFingerprintScore})
	if err != nil {
		b.Fatal(err)
	}
	response := probe.Result{
		StatusCode: 200,
		Protocol:   "HTTP/1.1",
		Headers:    []probe.HeaderField{{Name: "Content-Type", Values: []string{"text/html"}}},
		Body:       body,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		result := engine.Analyze(response)
		if result.Detected {
			b.Fatalf("negative corpus detected: %#v", result)
		}
	}
}

func TestAnalyzeLatencyPercentiles(t *testing.T) {
	body, err := os.ReadFile("testdata/elasticsearch-9.4.4.json")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(Options{Threshold: config.DefaultFingerprintScore})
	if err != nil {
		t.Fatal(err)
	}
	response := elasticResponse(body, true)
	for range 1_000 {
		if result := engine.Analyze(response); !result.Detected {
			t.Fatalf("warmup result = %#v", result)
		}
	}
	const samples = 10_000
	durations := make([]time.Duration, samples)
	for index := range durations {
		started := time.Now()
		result := engine.Analyze(response)
		durations[index] = time.Since(started)
		if !result.Detected {
			t.Fatalf("result = %#v", result)
		}
	}
	t.Logf("elasticsearch-9.4.4 p50=%s p95=%s p99=%s",
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
