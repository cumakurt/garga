package config

import (
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	maxConcurrency       = 1_000
	maxRequestsPerSecond = 10_000.0
	maxPerHostRate       = 1_000.0
	maxTimeout           = 5 * time.Minute
	maxRetries           = 10
	minResponseBytes     = 1_024
	maxResponseBytes     = 10 * 1024 * 1024
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
