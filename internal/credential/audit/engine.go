package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/ratelimit"
	"github.com/cumakurt/garga/internal/transport"
)

// Authenticator verifies one credential. Implementations must not retry 401/403.
type Authenticator interface {
	Verify(ctx context.Context, endpoint model.Endpoint, secret *credential.Secret) (credential.Result, error)
}

type requestLimiter interface {
	Wait(ctx context.Context, host string) error
}

// Engine runs an isolated, sequential credential audit against one endpoint.
type Engine struct {
	options Options
	auth    Authenticator
	limiter requestLimiter
	sleep   func(context.Context, time.Duration) error
}

// New creates an audit engine. It does not use scanner scheduling or scanner rates.
func New(options Options, authenticator Authenticator) (*Engine, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if authenticator == nil {
		return nil, fmt.Errorf("create credential audit engine: authenticator is required")
	}
	limiter, err := ratelimit.New(options.GlobalRate, options.PerHostRate)
	if err != nil {
		return nil, err
	}
	return &Engine{
		options: options,
		auth:    authenticator,
		limiter: limiter,
		sleep:   sleepContext,
	}, nil
}

// Run tries credentials in order until success, a hard stop, cancellation, or the attempt ceiling.
func (engine *Engine) Run(ctx context.Context, endpoint model.Endpoint, secrets []*credential.Secret) (Report, error) {
	if engine == nil || engine.auth == nil || engine.limiter == nil {
		return Report{}, fmt.Errorf("run credential audit: engine is not initialized")
	}
	if ctx == nil {
		return Report{}, fmt.Errorf("run credential audit: context is required")
	}
	if _, err := endpoint.URL(); err != nil {
		return Report{}, fmt.Errorf("run credential audit: endpoint is invalid")
	}
	if len(secrets) == 0 {
		return Report{}, fmt.Errorf("run credential audit: at least one credential is required")
	}
	if len(secrets) > maxCredentials {
		return Report{}, fmt.Errorf("run credential audit: at most %d credentials are allowed", maxCredentials)
	}

	report := Report{Events: make([]Event, 0, len(secrets))}
	for index, secret := range secrets {
		if secret == nil {
			return report, fmt.Errorf("run credential audit: credential is not initialized")
		}
		stopped, err := engine.trySecret(ctx, endpoint, secret, index, len(secrets), &report)
		if err != nil {
			return report, err
		}
		if stopped {
			return report, nil
		}
	}
	report.StopReason = StopCompleted
	return report, nil
}

func (engine *Engine) trySecret(
	ctx context.Context,
	endpoint model.Endpoint,
	secret *credential.Secret,
	index int,
	total int,
	report *Report,
) (bool, error) {
	for retry := 0; ; retry++ {
		if report.Attempts >= engine.options.MaxAttemptsPerHost {
			report.StopReason = StopCeiling
			return true, nil
		}
		if err := engine.limiter.Wait(ctx, endpoint.Host); err != nil {
			return true, engine.canceledOrWrapped(report, err, "wait for credential audit rate limit")
		}

		report.Attempts++
		result, err := engine.auth.Verify(ctx, endpoint, secret)
		report.Events = append(report.Events, newEvent(report.Attempts, endpoint, secret, result, err))

		if err != nil && ctx.Err() != nil {
			return true, engine.canceledOrWrapped(report, ctx.Err(), "verify credential")
		}
		if err == nil {
			switch result.Outcome {
			case credential.OutcomeValid:
				report.StopReason = StopSuccess
				return true, nil
			case credential.OutcomeSecurityUnavailable:
				report.StopReason = StopUnavailable
				return true, nil
			case credential.OutcomeInvalid:
				return engine.afterInvalid(ctx, endpoint, index, total, report)
			default:
				return true, fmt.Errorf("run credential audit: unexpected authenticate outcome")
			}
		}
		if shouldRetry(result.StatusCode, err) && retry < engine.options.TransientRetries {
			if err := engine.sleep(ctx, retryDelay(engine.options, endpoint, retry+1)); err != nil {
				return true, engine.canceledOrWrapped(report, err, "wait for credential audit backoff")
			}
			continue
		}
		if shouldRetry(result.StatusCode, err) {
			return engine.afterInvalid(ctx, endpoint, index, total, report)
		}
		message := "run credential audit: authenticate request failed"
		if kind, ok := transport.KindOf(err); ok {
			message = fmt.Sprintf("%s (%s)", message, kind)
		}
		return true, fmt.Errorf("%s", message)
	}
}

func (engine *Engine) afterInvalid(
	ctx context.Context,
	endpoint model.Endpoint,
	index int,
	total int,
	report *Report,
) (bool, error) {
	if report.Attempts >= engine.options.MaxAttemptsPerHost {
		report.StopReason = StopCeiling
		return true, nil
	}
	if index+1 >= total {
		return false, nil
	}
	if err := engine.sleep(ctx, retryDelay(engine.options, endpoint, report.Attempts)); err != nil {
		return true, engine.canceledOrWrapped(report, err, "wait for credential audit backoff")
	}
	return false, nil
}

func (engine *Engine) canceledOrWrapped(report *Report, err error, operation string) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		report.StopReason = StopCanceled
		return err
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func newEvent(attempt int, endpoint model.Endpoint, secret *credential.Secret, result credential.Result, err error) Event {
	outcome := result.Outcome
	if err != nil && outcome == "" {
		if shouldRetry(result.StatusCode, err) {
			outcome = OutcomeTransient
		} else {
			outcome = "error"
		}
	}
	return Event{
		Attempt:    attempt,
		Host:       endpoint.Host,
		Port:       endpoint.Port,
		Username:   secret.Username(),
		Mechanism:  secret.Kind(),
		Outcome:    outcome,
		StatusCode: result.StatusCode,
	}
}
