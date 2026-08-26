package scanner

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/config"
)

func TestOptionsFromConfig(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	options, err := OptionsFromConfig(cfg)
	if err != nil {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
	if options.Workers != cfg.Scanner.Concurrency || options.QueueCapacity != cfg.Scanner.Concurrency*2 {
		t.Fatalf("worker/queue options = %#v", options)
	}
	if options.GlobalRate != cfg.Scanner.RequestsPerSecond || options.PerHostRate != cfg.Scanner.PerHostRate {
		t.Fatalf("rate options = %#v", options)
	}
	if options.Retries != cfg.Scanner.Retries || options.RetryBaseBackoff <= 0 || options.RetryMaxBackoff < options.RetryBaseBackoff {
		t.Fatalf("retry options = %#v", options)
	}
}

func TestOptionsFromConfigRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Scanner.PerHostRate = 0
	_, err := OptionsFromConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "per_host_requests_per_second") {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
}

func TestOptionsValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"workers low", func(options *Options) { options.Workers = 0 }},
		{"workers high", func(options *Options) { options.Workers = maxWorkers + 1 }},
		{"queue low", func(options *Options) { options.QueueCapacity = 0 }},
		{"queue high", func(options *Options) { options.QueueCapacity = maxQueueCapacity + 1 }},
		{"global rate zero", func(options *Options) { options.GlobalRate = 0 }},
		{"global rate NaN", func(options *Options) { options.GlobalRate = math.NaN() }},
		{"per-host rate infinity", func(options *Options) { options.PerHostRate = math.Inf(1) }},
		{"per-host above global", func(options *Options) { options.PerHostRate = options.GlobalRate + 1 }},
		{"retries low", func(options *Options) { options.Retries = -1 }},
		{"retries high", func(options *Options) { options.Retries = maxRetries + 1 }},
		{"base backoff low", func(options *Options) { options.RetryBaseBackoff = 0 }},
		{"base backoff high", func(options *Options) { options.RetryBaseBackoff = maxRetryBackoff + time.Second }},
		{"maximum below base", func(options *Options) { options.RetryMaxBackoff = time.Millisecond }},
		{"maximum too high", func(options *Options) { options.RetryMaxBackoff = maxRetryBackoff + time.Second }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := scannerTestOptions(t)
			test.mutate(&options)
			if err := options.validate(); err == nil {
				t.Fatal("validate() returned nil")
			}
		})
	}
}
