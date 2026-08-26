package audit

import (
	"fmt"
	"math"
	"time"
)

const (
	DefaultMaxAttemptsPerHost = 5
	DefaultGlobalRate         = 1.0
	DefaultPerHostRate        = 1.0
	DefaultTransientRetries   = 1
	DefaultRetryBaseBackoff   = 200 * time.Millisecond
	DefaultRetryMaxBackoff    = 2 * time.Second

	maxAttemptsPerHost = 20
	maxCredentials     = 32
	maxAuditRate       = 1_000.0
	maxTransientRetry  = 5
	maxRetryBackoff    = time.Minute
	maxLineBytes       = 4096
	maxListBytes       = (maxCredentials + 32) * (maxLineBytes + 1)
)

// Options bounds an explicit credential audit. Scanner configuration does not apply.
type Options struct {
	MaxAttemptsPerHost int
	GlobalRate         float64
	PerHostRate        float64
	TransientRetries   int
	RetryBaseBackoff   time.Duration
	RetryMaxBackoff    time.Duration
}

// Defaults returns conservative audit limits. CLI callers must not raise rates above 1 req/s.
func Defaults() Options {
	return Options{
		MaxAttemptsPerHost: DefaultMaxAttemptsPerHost,
		GlobalRate:         DefaultGlobalRate,
		PerHostRate:        DefaultPerHostRate,
		TransientRetries:   DefaultTransientRetries,
		RetryBaseBackoff:   DefaultRetryBaseBackoff,
		RetryMaxBackoff:    DefaultRetryMaxBackoff,
	}
}

func (options Options) Validate() error {
	if options.MaxAttemptsPerHost < 1 || options.MaxAttemptsPerHost > maxAttemptsPerHost {
		return fmt.Errorf("invalid credential audit options: max attempts per host must be between 1 and %d", maxAttemptsPerHost)
	}
	if invalidRate(options.GlobalRate) {
		return fmt.Errorf("invalid credential audit options: global rate must be greater than zero and at most %g", maxAuditRate)
	}
	if invalidRate(options.PerHostRate) || options.PerHostRate > options.GlobalRate {
		return fmt.Errorf("invalid credential audit options: per-host rate must be greater than zero, at most %g, and no greater than the global rate", maxAuditRate)
	}
	if options.TransientRetries < 0 || options.TransientRetries > maxTransientRetry {
		return fmt.Errorf("invalid credential audit options: transient retries must be between 0 and %d", maxTransientRetry)
	}
	if options.RetryBaseBackoff <= 0 || options.RetryBaseBackoff > maxRetryBackoff {
		return fmt.Errorf("invalid credential audit options: retry base backoff must be greater than zero and at most %s", maxRetryBackoff)
	}
	if options.RetryMaxBackoff < options.RetryBaseBackoff || options.RetryMaxBackoff > maxRetryBackoff {
		return fmt.Errorf("invalid credential audit options: retry maximum backoff must be at least the base and at most %s", maxRetryBackoff)
	}
	return nil
}

func invalidRate(value float64) bool {
	return math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value > maxAuditRate
}
