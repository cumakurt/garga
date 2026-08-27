package config

import (
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	maxConcurrency         = 1_000
	maxRequestsPerSecond   = 10_000.0
	maxPerHostRate         = 1_000.0
	maxTimeout             = 5 * time.Minute
	maxRetries             = 10
	minResponseBytes       = 1_024
	maxResponseBytes       = 10 * 1024 * 1024
	maxHealthResponseBytes = 128 * 1024 * 1024
)

// ValidationError reports all configuration violations in deterministic field order.
type ValidationError struct {
	problems []string
}

func (err *ValidationError) Error() string {
	return "invalid configuration: " + strings.Join(err.problems, "; ")
}

// Validate rejects unsafe or unusable settings before network execution begins.
func (cfg Config) Validate() error {
	var problems []string

	if cfg.Scanner.Concurrency < 1 || cfg.Scanner.Concurrency > maxConcurrency {
		problems = append(problems, fmt.Sprintf("scanner.concurrency must be between 1 and %d", maxConcurrency))
	}
	if math.IsNaN(cfg.Scanner.RequestsPerSecond) || math.IsInf(cfg.Scanner.RequestsPerSecond, 0) || cfg.Scanner.RequestsPerSecond <= 0 || cfg.Scanner.RequestsPerSecond > maxRequestsPerSecond {
		problems = append(problems, fmt.Sprintf("scanner.requests_per_second must be greater than 0 and at most %g", maxRequestsPerSecond))
	}
	if math.IsNaN(cfg.Scanner.PerHostRate) || math.IsInf(cfg.Scanner.PerHostRate, 0) || cfg.Scanner.PerHostRate <= 0 || cfg.Scanner.PerHostRate > maxPerHostRate {
		problems = append(problems, fmt.Sprintf("scanner.per_host_requests_per_second must be greater than 0 and at most %g", maxPerHostRate))
	} else if cfg.Scanner.PerHostRate > cfg.Scanner.RequestsPerSecond {
		problems = append(problems, "scanner.per_host_requests_per_second must not exceed scanner.requests_per_second")
	}
	if cfg.Scanner.ConnectTimeout <= 0 || cfg.Scanner.ConnectTimeout > maxTimeout {
		problems = append(problems, fmt.Sprintf("scanner.connect_timeout must be greater than 0 and at most %s", maxTimeout))
	}
	if cfg.Scanner.RequestTimeout <= 0 || cfg.Scanner.RequestTimeout > maxTimeout {
		problems = append(problems, fmt.Sprintf("scanner.request_timeout must be greater than 0 and at most %s", maxTimeout))
	}
	if cfg.Scanner.ConnectTimeout > cfg.Scanner.RequestTimeout {
		problems = append(problems, "scanner.connect_timeout must not exceed scanner.request_timeout")
	}
	if cfg.Scanner.Retries < 0 || cfg.Scanner.Retries > maxRetries {
		problems = append(problems, fmt.Sprintf("scanner.retries must be between 0 and %d", maxRetries))
	}
	if cfg.Scanner.MaxResponseBytes < minResponseBytes || cfg.Scanner.MaxResponseBytes > maxResponseBytes {
		problems = append(problems, fmt.Sprintf("scanner.max_response_bytes must be between %d and %d", minResponseBytes, maxResponseBytes))
	}
	if cfg.Fingerprint.Threshold < 1 || cfg.Fingerprint.Threshold > 100 {
		problems = append(problems, "fingerprint.threshold must be between 1 and 100")
	}

	switch cfg.Health.Profile {
	case HealthProfileDevelopment, HealthProfileSmall, HealthProfileStandard, HealthProfileLarge,
		HealthProfileLogging, HealthProfileSearch, HealthProfileSecurity, HealthProfileProduction:
	default:
		problems = append(problems, "health.profile must be one of development, small, standard, large, logging, search, security, or production")
	}
	if cfg.Health.Concurrency < 1 || cfg.Health.Concurrency > 32 {
		problems = append(problems, "health.concurrency must be between 1 and 32")
	}
	if math.IsNaN(cfg.Health.RequestsPerSecond) || math.IsInf(cfg.Health.RequestsPerSecond, 0) || cfg.Health.RequestsPerSecond <= 0 || cfg.Health.RequestsPerSecond > 100 {
		problems = append(problems, "health.requests_per_second must be greater than 0 and at most 100")
	}
	if cfg.Health.TopN < 1 || cfg.Health.TopN > 100 {
		problems = append(problems, "health.top_n must be between 1 and 100")
	}
	if cfg.Health.MaxResponseBytes < minResponseBytes || cfg.Health.MaxResponseBytes > maxHealthResponseBytes {
		problems = append(problems, fmt.Sprintf("health.max_response_bytes must be between %d and %d", minResponseBytes, maxHealthResponseBytes))
	}
	validatePercentThreshold := func(name string, threshold PercentThreshold) {
		if invalidPercent(threshold.Warning) || invalidPercent(threshold.High) || invalidPercent(threshold.Critical) ||
			threshold.Warning >= threshold.High || threshold.High >= threshold.Critical {
			problems = append(problems, name+" must satisfy 0 <= warning < high < critical <= 100")
		}
	}
	validatePercentThreshold("health.thresholds.jvm", cfg.Health.Thresholds.JVM)
	validatePercentThreshold("health.thresholds.memory", cfg.Health.Thresholds.Memory)
	validatePercentThreshold("health.thresholds.disk", cfg.Health.Thresholds.Disk)
	validatePercentThreshold("health.thresholds.cpu", cfg.Health.Thresholds.CPU)
	validatePercentThreshold("health.thresholds.file_descriptors", cfg.Health.Thresholds.FileDescriptors)
	deleted := cfg.Health.Thresholds.DeletedDocuments
	if math.IsNaN(deleted.Warning) || math.IsNaN(deleted.High) || deleted.Warning <= 0 || deleted.High <= deleted.Warning || deleted.High > 1 {
		problems = append(problems, "health.thresholds.deleted_documents must satisfy 0 < warning < high <= 1")
	}
	shardSize := cfg.Health.Thresholds.ShardSize
	if shardSize.Small <= 0 || shardSize.LargeWarning <= shardSize.Small || shardSize.LargeHigh <= shardSize.LargeWarning {
		problems = append(problems, "health.thresholds.shard_size must satisfy 0 < small < large_warning < large_high")
	}
	validateVariation := func(name string, threshold VariationThreshold) {
		if math.IsNaN(threshold.Warning) || math.IsNaN(threshold.High) || threshold.Warning <= 0 || threshold.High <= threshold.Warning {
			problems = append(problems, name+" must satisfy 0 < warning < high")
		}
	}
	validateVariation("health.thresholds.shard_imbalance", cfg.Health.Thresholds.ShardImbalance)
	validateVariation("health.thresholds.disk_imbalance", cfg.Health.Thresholds.DiskImbalance)
	certificate := cfg.Health.Thresholds.Certificate
	if certificate.Critical < 0 || certificate.High <= certificate.Critical || certificate.Warning <= certificate.High {
		problems = append(problems, "health.thresholds.certificate must satisfy 0 <= critical < high < warning")
	}
	if cfg.Health.Thresholds.PendingTaskWarning <= 0 || cfg.Health.Thresholds.PendingTaskHigh <= cfg.Health.Thresholds.PendingTaskWarning {
		problems = append(problems, "health pending-task thresholds must satisfy 0 < warning < high")
	}
	if cfg.Health.Thresholds.LongTaskWarning <= 0 {
		problems = append(problems, "health.thresholds.long_task_warning must be greater than 0")
	}
	if cfg.Health.Thresholds.BackupWarning <= 0 || cfg.Health.Thresholds.BackupHigh <= cfg.Health.Thresholds.BackupWarning {
		problems = append(problems, "health backup thresholds must satisfy 0 < warning < high")
	}
	if cfg.Health.Thresholds.ThreadPoolQueueHigh < 1 {
		problems = append(problems, "health.thresholds.thread_pool_queue_high must be positive")
	}

	switch cfg.Output.Format {
	case OutputConsole, OutputJSON, OutputJSONL, OutputCSV, OutputHTML:
	default:
		problems = append(problems, "output.format must be one of console, json, jsonl, csv, or html")
	}

	switch cfg.Logging.Level {
	case LogError, LogWarn, LogInfo, LogDebug:
	default:
		problems = append(problems, "logging.level must be one of error, warn, info, or debug")
	}

	if len(problems) > 0 {
		return &ValidationError{problems: problems}
	}
	return nil
}

func invalidPercent(value float64) bool {
	return math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 100
}
