package detect

import (
	"fmt"
	"math"
	"time"
)

const (
	DefaultMaxAttemptsPerHost = 100
	DefaultGlobalRate         = 1.0
	DefaultPerHostRate        = 1.0
	DefaultTransientRetries   = 1
	DefaultRetryBaseBackoff   = 200 * time.Millisecond
	DefaultRetryMaxBackoff    = 2 * time.Second

	maxAttemptsPerHost = 1_000
	maxUsers           = 256
	maxPasswords       = 256
	maxPairs           = 512
	maxAuditRate       = 1_000.0
	maxTransientRetry  = 5
	maxRetryBackoff    = time.Minute
	maxSprayDelay      = 5 * time.Minute
	maxLineBytes       = 4096
	maxUsersListBytes  = (maxUsers + 32) * (maxLineBytes + 1)
	maxPasswordsBytes  = (maxPasswords + 32) * (maxLineBytes + 1)
	maxPairsListBytes  = (maxPairs + 32) * (maxLineBytes + 1)
)

// Options bounds an explicit credential detection run. Scanner configuration does not apply.
type Options struct {
	Mode               Mode
	MaxAttemptsPerHost int
	GlobalRate         float64
	PerHostRate        float64
	TransientRetries   int
	RetryBaseBackoff   time.Duration
	RetryMaxBackoff    time.Duration
	StopOnSuccess      bool
	SprayRoundSize     int
	SprayRoundDelay    time.Duration
}

// Defaults returns conservative detection limits. CLI callers must not raise rates above 1 req/s.
func Defaults() Options {
	return Options{
		Mode:               ModeStuffing,
		MaxAttemptsPerHost: DefaultMaxAttemptsPerHost,
		GlobalRate:         DefaultGlobalRate,
		PerHostRate:        DefaultPerHostRate,
		TransientRetries:   DefaultTransientRetries,
		RetryBaseBackoff:   DefaultRetryBaseBackoff,
		RetryMaxBackoff:    DefaultRetryMaxBackoff,
		StopOnSuccess:      true,
	}
}

func (options Options) Validate() error {
	switch options.Mode {
	case ModeStuffing, ModeSpraying, ModeBruteForce, ModeDictionary:
	default:
		return fmt.Errorf("invalid credential detection options: mode is required")
	}
	if options.MaxAttemptsPerHost < 1 || options.MaxAttemptsPerHost > maxAttemptsPerHost {
		return fmt.Errorf("invalid credential detection options: max attempts per host must be between 1 and %d", maxAttemptsPerHost)
	}
	if invalidRate(options.GlobalRate) {
		return fmt.Errorf("invalid credential detection options: global rate must be greater than zero and at most %g", maxAuditRate)
	}
	if invalidRate(options.PerHostRate) || options.PerHostRate > options.GlobalRate {
		return fmt.Errorf("invalid credential detection options: per-host rate must be greater than zero, at most %g, and no greater than the global rate", maxAuditRate)
	}
	if options.TransientRetries < 0 || options.TransientRetries > maxTransientRetry {
		return fmt.Errorf("invalid credential detection options: transient retries must be between 0 and %d", maxTransientRetry)
	}
	if options.RetryBaseBackoff <= 0 || options.RetryBaseBackoff > maxRetryBackoff {
		return fmt.Errorf("invalid credential detection options: retry base backoff must be greater than zero and at most %s", maxRetryBackoff)
	}
	if options.RetryMaxBackoff < options.RetryBaseBackoff || options.RetryMaxBackoff > maxRetryBackoff {
		return fmt.Errorf("invalid credential detection options: retry maximum backoff must be at least the base and at most %s", maxRetryBackoff)
	}
	if options.SprayRoundDelay < 0 || options.SprayRoundDelay > maxSprayDelay {
		return fmt.Errorf("invalid credential detection options: spray delay must be between 0 and %s", maxSprayDelay)
	}
	if options.SprayRoundSize < 0 || options.SprayRoundSize > maxUsers {
		return fmt.Errorf("invalid credential detection options: spray round size must be between 0 and %d", maxUsers)
	}
	if options.Mode != ModeSpraying && (options.SprayRoundSize > 0 || options.SprayRoundDelay > 0) {
		return fmt.Errorf("invalid credential detection options: spray delay applies only to spraying mode")
	}
	return nil
}

func invalidRate(value float64) bool {
	return math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value > maxAuditRate
}
