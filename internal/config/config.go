package config

import (
	"fmt"
	"strings"
	"time"
)

const (
	DefaultConcurrency       = 20
	DefaultRequestsPerSecond = 50.0
	DefaultPerHostRate       = 5.0
	DefaultConnectTimeout    = 2 * time.Second
	DefaultRequestTimeout    = 5 * time.Second
	DefaultRetries           = 1
	DefaultMaxResponseBytes  = 512 * 1024
	DefaultFingerprintScore  = 80
)

// OutputFormat identifies a supported report encoding.
type OutputFormat string

const (
	OutputConsole OutputFormat = "console"
	OutputJSON    OutputFormat = "json"
	OutputJSONL   OutputFormat = "jsonl"
	OutputCSV     OutputFormat = "csv"
	OutputHTML    OutputFormat = "html"
)

// LogLevel controls application logging verbosity.
type LogLevel string

const (
	LogError LogLevel = "error"
	LogWarn  LogLevel = "warn"
	LogInfo  LogLevel = "info"
	LogDebug LogLevel = "debug"
)

const DefaultLogLevel = LogWarn

// Config contains non-secret operational settings. Authentication material is
// intentionally modeled outside this type so generic formatting cannot expose it.
type Config struct {
	Scanner     ScannerConfig
	Fingerprint FingerprintConfig
	Output      OutputConfig
	Logging     LoggingConfig
}

type ScannerConfig struct {
	Concurrency       int
	RequestsPerSecond float64
	PerHostRate       float64
	ConnectTimeout    time.Duration
	RequestTimeout    time.Duration
	Retries           int
	MaxResponseBytes  int64
}

type FingerprintConfig struct {
	Threshold int
}

type OutputConfig struct {
	Format OutputFormat
}

type LoggingConfig struct {
	Level LogLevel
}

// Overrides represents values explicitly supplied by a CLI layer. Pointer
// fields distinguish an omitted option from an explicit zero value.
type Overrides struct {
	Concurrency       *int
	RequestsPerSecond *float64
	PerHostRate       *float64
	ConnectTimeout    *time.Duration
	RequestTimeout    *time.Duration
	Retries           *int
	MaxResponseBytes  *int64
	FingerprintScore  *int
	OutputFormat      *OutputFormat
	LogLevel          *LogLevel
}

// Defaults returns a complete, validated configuration suitable for normal scans.
func Defaults() Config {
	return Config{
		Scanner: ScannerConfig{
			Concurrency:       DefaultConcurrency,
			RequestsPerSecond: DefaultRequestsPerSecond,
			PerHostRate:       DefaultPerHostRate,
			ConnectTimeout:    DefaultConnectTimeout,
			RequestTimeout:    DefaultRequestTimeout,
			Retries:           DefaultRetries,
			MaxResponseBytes:  DefaultMaxResponseBytes,
		},
		Fingerprint: FingerprintConfig{Threshold: DefaultFingerprintScore},
		Output:      OutputConfig{Format: OutputConsole},
		Logging:     LoggingConfig{Level: DefaultLogLevel},
	}
}

// String returns a deterministic representation containing operational values only.
func (cfg Config) String() string {
	outputFormat := cfg.Output.Format
	switch outputFormat {
	case OutputConsole, OutputJSON, OutputJSONL, OutputCSV, OutputHTML:
	default:
		outputFormat = "<invalid>"
	}
	logLevel := cfg.Logging.Level
	switch logLevel {
	case LogError, LogWarn, LogInfo, LogDebug:
	default:
		logLevel = "<invalid>"
	}

	return fmt.Sprintf(
		"scanner.concurrency=%d scanner.requests_per_second=%g scanner.per_host_requests_per_second=%g scanner.connect_timeout=%s scanner.request_timeout=%s scanner.retries=%d scanner.max_response_bytes=%d fingerprint.threshold=%d output.format=%s logging.level=%s",
		cfg.Scanner.Concurrency,
		cfg.Scanner.RequestsPerSecond,
		cfg.Scanner.PerHostRate,
		cfg.Scanner.ConnectTimeout,
		cfg.Scanner.RequestTimeout,
		cfg.Scanner.Retries,
		cfg.Scanner.MaxResponseBytes,
		cfg.Fingerprint.Threshold,
		outputFormat,
		logLevel,
	)
}

func parseOutputFormat(value string) OutputFormat {
	return OutputFormat(strings.ToLower(strings.TrimSpace(value)))
}

func parseLogLevel(value string) LogLevel {
	return LogLevel(strings.ToLower(strings.TrimSpace(value)))
}
