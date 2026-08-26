package scanner

import (
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/cumakurt/garga/internal/config"
)

const (
	maxWorkers       = 1_000
	maxQueueCapacity = 100_000
	maxRate          = 10_000.0
	maxRetries       = 10
	maxRetryBackoff  = time.Minute
	defaultRetryBase = 100 * time.Millisecond
	defaultRetryMax  = 2 * time.Second
)

// Options controls bounded scheduling, rate limiting, and transient retries.
type Options struct {
	Workers          int
	QueueCapacity    int
	GlobalRate       float64
	PerHostRate      float64
	Retries          int
	RetryBaseBackoff time.Duration
	RetryMaxBackoff  time.Duration
	Logger           *slog.Logger
}

// OptionsFromConfig derives scanner limits from validated application configuration.
func OptionsFromConfig(cfg config.Config) (Options, error) {
	if err := cfg.Validate(); err != nil {
		return Options{}, err
	}
	return Options{
		Workers:          cfg.Scanner.Concurrency,
		QueueCapacity:    cfg.Scanner.Concurrency * 2,
		GlobalRate:       cfg.Scanner.RequestsPerSecond,
		PerHostRate:      cfg.Scanner.PerHostRate,
		Retries:          cfg.Scanner.Retries,
		RetryBaseBackoff: defaultRetryBase,
		RetryMaxBackoff:  defaultRetryMax,
	}, nil
}

func (options Options) validate() error {
	if options.Workers < 1 || options.Workers > maxWorkers {
		return fmt.Errorf("invalid scanner options: workers must be between 1 and %d", maxWorkers)
	}
	if options.QueueCapacity < 1 || options.QueueCapacity > maxQueueCapacity {
		return fmt.Errorf("invalid scanner options: queue capacity must be between 1 and %d", maxQueueCapacity)
	}
	if invalidRate(options.GlobalRate) {
		return fmt.Errorf("invalid scanner options: global rate must be greater than zero and at most %g", maxRate)
	}
	if invalidRate(options.PerHostRate) || options.PerHostRate > options.GlobalRate {
		return fmt.Errorf("invalid scanner options: per-host rate must be greater than zero, at most %g, and no greater than the global rate", maxRate)
	}
	if options.Retries < 0 || options.Retries > maxRetries {
		return fmt.Errorf("invalid scanner options: retries must be between 0 and %d", maxRetries)
	}
	if options.RetryBaseBackoff <= 0 || options.RetryBaseBackoff > maxRetryBackoff {
		return fmt.Errorf("invalid scanner options: retry base backoff must be greater than zero and at most %s", maxRetryBackoff)
	}
	if options.RetryMaxBackoff < options.RetryBaseBackoff || options.RetryMaxBackoff > maxRetryBackoff {
		return fmt.Errorf("invalid scanner options: retry maximum backoff must be at least the base and at most %s", maxRetryBackoff)
	}
	return nil
}

func invalidRate(value float64) bool {
	return math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value > maxRate
}
