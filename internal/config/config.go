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
	DefaultHealthConcurrency = 4
	DefaultHealthRate        = 5.0
	DefaultHealthTopN        = 5
	DefaultHealthMaxResponse = 32 * 1024 * 1024
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
	Health      HealthConfig
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

// HealthConfig contains non-secret limits and heuristics for one cluster assessment.
type HealthConfig struct {
	Profile           HealthProfile
	Concurrency       int
	RequestsPerSecond float64
	TopN              int
	MaxResponseBytes  int64
	Thresholds        HealthThresholds
}

type HealthProfile string

const (
	HealthProfileDevelopment HealthProfile = "development"
	HealthProfileSmall       HealthProfile = "small"
	HealthProfileStandard    HealthProfile = "standard"
	HealthProfileLarge       HealthProfile = "large"
	HealthProfileLogging     HealthProfile = "logging"
	HealthProfileSearch      HealthProfile = "search"
	HealthProfileSecurity    HealthProfile = "security"
	HealthProfileProduction  HealthProfile = "production"
)

type HealthThresholds struct {
	JVM                 PercentThreshold
	Memory              PercentThreshold
	Disk                PercentThreshold
	CPU                 PercentThreshold
	FileDescriptors     PercentThreshold
	DeletedDocuments    RatioThreshold
	ShardSize           ShardSizeThreshold
	ShardImbalance      VariationThreshold
	DiskImbalance       VariationThreshold
	Certificate         DaysThreshold
	PendingTaskWarning  time.Duration
	PendingTaskHigh     time.Duration
	LongTaskWarning     time.Duration
	BackupWarning       time.Duration
	BackupHigh          time.Duration
	ThreadPoolQueueHigh int
}

type PercentThreshold struct {
	Warning  float64
	High     float64
	Critical float64
}

type RatioThreshold struct {
	Warning float64
	High    float64
}

type ShardSizeThreshold struct {
	Small        int64
	LargeWarning int64
	LargeHigh    int64
}

type VariationThreshold struct {
	Warning float64
	High    float64
}

type DaysThreshold struct {
	Warning  int
	High     int
	Critical int
}

type OutputConfig struct {
	Format OutputFormat
	// HTMLReport also writes the timestamped HTML CWD artifact. PDF is always written.
	HTMLReport bool
}

type LoggingConfig struct {
	Level LogLevel
}

// Overrides represents values explicitly supplied by a CLI layer. Pointer
// fields distinguish an omitted option from an explicit zero value.
type Overrides struct {
	Concurrency            *int
	RequestsPerSecond      *float64
	PerHostRate            *float64
	ConnectTimeout         *time.Duration
	RequestTimeout         *time.Duration
	Retries                *int
	MaxResponseBytes       *int64
	FingerprintScore       *int
	HealthProfile          *HealthProfile
	HealthConcurrency      *int
	HealthRate             *float64
	HealthTopN             *int
	HealthMaxResponseBytes *int64
	OutputFormat           *OutputFormat
	HTMLReport             *bool
	LogLevel               *LogLevel
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
		Health: HealthConfig{
			Profile:           HealthProfileStandard,
			Concurrency:       DefaultHealthConcurrency,
			RequestsPerSecond: DefaultHealthRate,
			TopN:              DefaultHealthTopN,
			MaxResponseBytes:  DefaultHealthMaxResponse,
			Thresholds: HealthThresholds{
				JVM:                 PercentThreshold{Warning: 75, High: 85, Critical: 95},
				Memory:              PercentThreshold{Warning: 90, High: 95, Critical: 98},
				Disk:                PercentThreshold{Warning: 75, High: 85, Critical: 95},
				CPU:                 PercentThreshold{Warning: 75, High: 90, Critical: 98},
				FileDescriptors:     PercentThreshold{Warning: 70, High: 85, Critical: 95},
				DeletedDocuments:    RatioThreshold{Warning: 0.20, High: 0.40},
				ShardSize:           ShardSizeThreshold{Small: 1024 * 1024 * 1024, LargeWarning: 50 * 1024 * 1024 * 1024, LargeHigh: 100 * 1024 * 1024 * 1024},
				ShardImbalance:      VariationThreshold{Warning: 0.25, High: 0.50},
				DiskImbalance:       VariationThreshold{Warning: 15, High: 30},
				Certificate:         DaysThreshold{Warning: 30, High: 14, Critical: 7},
				PendingTaskWarning:  30 * time.Second,
				PendingTaskHigh:     2 * time.Minute,
				LongTaskWarning:     30 * time.Minute,
				BackupWarning:       3 * 24 * time.Hour,
				BackupHigh:          7 * 24 * time.Hour,
				ThreadPoolQueueHigh: 100,
			},
		},
		Output:  OutputConfig{Format: OutputConsole},
		Logging: LoggingConfig{Level: DefaultLogLevel},
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
	healthProfile := cfg.Health.Profile
	switch healthProfile {
	case HealthProfileDevelopment, HealthProfileSmall, HealthProfileStandard, HealthProfileLarge,
		HealthProfileLogging, HealthProfileSearch, HealthProfileSecurity, HealthProfileProduction:
	default:
		healthProfile = "<invalid>"
	}

	return fmt.Sprintf(
		"scanner.concurrency=%d scanner.requests_per_second=%g scanner.per_host_requests_per_second=%g scanner.connect_timeout=%s scanner.request_timeout=%s scanner.retries=%d scanner.max_response_bytes=%d fingerprint.threshold=%d health.profile=%s health.concurrency=%d health.requests_per_second=%g health.top_n=%d health.max_response_bytes=%d output.format=%s output.html_report=%t logging.level=%s",
		cfg.Scanner.Concurrency,
		cfg.Scanner.RequestsPerSecond,
		cfg.Scanner.PerHostRate,
		cfg.Scanner.ConnectTimeout,
		cfg.Scanner.RequestTimeout,
		cfg.Scanner.Retries,
		cfg.Scanner.MaxResponseBytes,
		cfg.Fingerprint.Threshold,
		healthProfile,
		cfg.Health.Concurrency,
		cfg.Health.RequestsPerSecond,
		cfg.Health.TopN,
		cfg.Health.MaxResponseBytes,
		outputFormat,
		cfg.Output.HTMLReport,
		logLevel,
	)
}

func parseOutputFormat(value string) OutputFormat {
	return OutputFormat(strings.ToLower(strings.TrimSpace(value)))
}

func parseLogLevel(value string) LogLevel {
	return LogLevel(strings.ToLower(strings.TrimSpace(value)))
}

func parseHealthProfile(value string) HealthProfile {
	return HealthProfile(strings.ToLower(strings.TrimSpace(value)))
}
