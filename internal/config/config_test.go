package config

import (
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	t.Parallel()

	want := Config{
		Scanner: ScannerConfig{
			Concurrency:       20,
			RequestsPerSecond: 50,
			PerHostRate:       5,
			ConnectTimeout:    2 * time.Second,
			RequestTimeout:    5 * time.Second,
			Retries:           1,
			MaxResponseBytes:  512 * 1024,
		},
		Fingerprint: FingerprintConfig{Threshold: 80},
		Output:      OutputConfig{Format: OutputConsole},
		Logging:     LoggingConfig{Level: LogInfo},
	}

	if got := Defaults(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Defaults() = %#v, want %#v", got, want)
	}
	if err := want.Validate(); err != nil {
		t.Fatalf("default configuration must be valid: %v", err)
	}
}

func TestConfigStringIsDeterministicAndSecretSafe(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	cfg := Defaults()
	cfg.Output.Format = OutputFormat(canary)
	cfg.Logging.Level = LogLevel(canary)

	got := cfg.String()
	if strings.Contains(got, canary) {
		t.Fatalf("formatted configuration exposed canary: %q", got)
	}
	if !strings.Contains(got, "output.format=<invalid> logging.level=<invalid>") {
		t.Fatalf("formatted configuration did not sanitize invalid enum values: %q", got)
	}
}

func TestValidateRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Config)
		message string
	}{
		{"zero concurrency", func(cfg *Config) { cfg.Scanner.Concurrency = 0 }, "scanner.concurrency"},
		{"excessive concurrency", func(cfg *Config) { cfg.Scanner.Concurrency = 1_001 }, "scanner.concurrency"},
		{"zero rate", func(cfg *Config) { cfg.Scanner.RequestsPerSecond = 0 }, "scanner.requests_per_second"},
		{"nan rate", func(cfg *Config) { cfg.Scanner.RequestsPerSecond = math.NaN() }, "scanner.requests_per_second"},
		{"infinite rate", func(cfg *Config) { cfg.Scanner.RequestsPerSecond = math.Inf(1) }, "scanner.requests_per_second"},
		{"zero per-host rate", func(cfg *Config) { cfg.Scanner.PerHostRate = 0 }, "scanner.per_host_requests_per_second"},
		{"nan per-host rate", func(cfg *Config) { cfg.Scanner.PerHostRate = math.NaN() }, "scanner.per_host_requests_per_second"},
		{"per-host rate above global", func(cfg *Config) { cfg.Scanner.PerHostRate = 51 }, "must not exceed"},
		{"zero connect timeout", func(cfg *Config) { cfg.Scanner.ConnectTimeout = 0 }, "scanner.connect_timeout"},
		{"connect exceeds request", func(cfg *Config) { cfg.Scanner.ConnectTimeout = 6 * time.Second }, "must not exceed"},
		{"zero request timeout", func(cfg *Config) { cfg.Scanner.RequestTimeout = 0 }, "scanner.request_timeout"},
		{"negative retries", func(cfg *Config) { cfg.Scanner.Retries = -1 }, "scanner.retries"},
		{"small response limit", func(cfg *Config) { cfg.Scanner.MaxResponseBytes = 100 }, "scanner.max_response_bytes"},
		{"large response limit", func(cfg *Config) { cfg.Scanner.MaxResponseBytes = 11 * 1024 * 1024 }, "scanner.max_response_bytes"},
		{"zero fingerprint score", func(cfg *Config) { cfg.Fingerprint.Threshold = 0 }, "fingerprint.threshold"},
		{"invalid output", func(cfg *Config) { cfg.Output.Format = "xml" }, "output.format"},
		{"invalid log level", func(cfg *Config) { cfg.Logging.Level = "verbose" }, "logging.level"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			test.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() returned nil")
			}
			if !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %q, want substring %q", err, test.message)
			}
		})
	}
}

func TestValidateReportsProblemsInFieldOrder(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	cfg.Scanner.Concurrency = 0
	cfg.Scanner.Retries = -1
	cfg.Output.Format = "xml"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() returned nil")
	}
	message := err.Error()
	concurrencyIndex := strings.Index(message, "scanner.concurrency")
	retriesIndex := strings.Index(message, "scanner.retries")
	outputIndex := strings.Index(message, "output.format")
	if concurrencyIndex < 0 || retriesIndex <= concurrencyIndex || outputIndex <= retriesIndex {
		t.Fatalf("validation errors are not in field order: %q", message)
	}
}
