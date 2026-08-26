package audit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/transport"
)

func TestAuditStopsOnSuccessAndSkipsRemaining(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	secrets := []*credential.Secret{
		mustBasic(t, "alice", canary+"-1"),
		mustBasic(t, "bob", canary+"-2"),
		mustBasic(t, "carol", canary+"-3"),
	}
	auth := &scriptedAuth{statuses: []int{http.StatusUnauthorized, http.StatusOK, http.StatusOK}}
	engine := newTestEngine(t, testOptions(), auth)

	report, err := engine.Run(context.Background(), testEndpoint(), secrets)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if auth.calls.Load() != 2 {
		t.Fatalf("verify calls = %d, want 2", auth.calls.Load())
	}
	if report.StopReason != StopSuccess || report.Attempts != 2 {
		t.Fatalf("report = %#v", report)
	}
	assertNoCanary(t, report, canary)
}

func TestAuditDoesNotRetryUnauthorized(t *testing.T) {
	t.Parallel()

	secret := mustBasic(t, "alice", "credential-canary")
	auth := &scriptedAuth{statuses: []int{http.StatusUnauthorized, http.StatusUnauthorized}}
	options := testOptions()
	options.TransientRetries = 5
	engine := newTestEngine(t, options, auth)

	report, err := engine.Run(context.Background(), testEndpoint(), []*credential.Secret{secret})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if auth.calls.Load() != 1 {
		t.Fatalf("verify calls = %d, want 1", auth.calls.Load())
	}
	if report.StopReason != StopCompleted || report.Attempts != 1 {
		t.Fatalf("report = %#v", report)
	}
}

func TestRetriesCannotBypassAttemptCeiling(t *testing.T) {
	t.Parallel()

	secrets := []*credential.Secret{
		mustBasic(t, "alice", "credential-canary-1"),
		mustBasic(t, "bob", "credential-canary-2"),
	}
	auth := &scriptedAuth{statuses: []int{
		http.StatusServiceUnavailable,
		http.StatusServiceUnavailable,
		http.StatusServiceUnavailable,
		http.StatusServiceUnavailable,
	}}
	options := testOptions()
	options.MaxAttemptsPerHost = 2
	options.TransientRetries = 5
	limiter := &countingLimiter{}
	engine := newTestEngine(t, options, auth)
	engine.limiter = limiter

	report, err := engine.Run(context.Background(), testEndpoint(), secrets)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := auth.calls.Load(); got != 2 {
		t.Fatalf("verify calls = %d, want 2", got)
	}
	if got := limiter.waits.Load(); got != 2 {
		t.Fatalf("rate-limit waits = %d, want 2", got)
	}
	if report.StopReason != StopCeiling || report.Attempts != 2 {
		t.Fatalf("report = %#v", report)
	}
}

func TestRetriesCannotBypassRateLimiter(t *testing.T) {
	t.Parallel()

	secret := mustBasic(t, "alice", "credential-canary")
	auth := &scriptedAuth{statuses: []int{http.StatusTooManyRequests, http.StatusTooManyRequests, http.StatusUnauthorized}}
	options := testOptions()
	options.MaxAttemptsPerHost = 5
	options.TransientRetries = 2
	limiter := &countingLimiter{}
	engine := newTestEngine(t, options, auth)
	engine.limiter = limiter

	report, err := engine.Run(context.Background(), testEndpoint(), []*credential.Secret{secret})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := auth.calls.Load(); got != 3 {
		t.Fatalf("verify calls = %d, want 3", got)
	}
	if got := limiter.waits.Load(); got != 3 {
		t.Fatalf("rate-limit waits = %d, want 3", got)
	}
	if report.StopReason != StopCompleted {
		t.Fatalf("report = %#v", report)
	}
}

func TestAuditStopsWhenSecurityUnavailable(t *testing.T) {
	t.Parallel()

	secrets := []*credential.Secret{
		mustBasic(t, "alice", "credential-canary-1"),
		mustBasic(t, "bob", "credential-canary-2"),
	}
	auth := &scriptedAuth{statuses: []int{http.StatusNotFound, http.StatusOK}}
	engine := newTestEngine(t, testOptions(), auth)

	report, err := engine.Run(context.Background(), testEndpoint(), secrets)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if auth.calls.Load() != 1 || report.StopReason != StopUnavailable {
		t.Fatalf("calls = %d report = %#v", auth.calls.Load(), report)
	}
}

func TestAuditHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secret := mustBasic(t, "alice", "credential-canary")
	engine := newTestEngine(t, testOptions(), verifyFunc(func(ctx context.Context, _ model.Endpoint, _ *credential.Secret) (credential.Result, error) {
		cancel()
		return credential.Result{}, ctx.Err()
	}))

	report, err := engine.Run(ctx, testEndpoint(), []*credential.Secret{secret})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	if report.StopReason != StopCanceled {
		t.Fatalf("report = %#v", report)
	}
}

func TestAuditRejectsNilAuthenticator(t *testing.T) {
	t.Parallel()

	if _, err := New(testOptions(), nil); err == nil {
		t.Fatal("New(nil authenticator) succeeded")
	}
}

func TestFormatEventOmitsSecrets(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	event := Event{
		Attempt:    1,
		Host:       "192.0.2.10",
		Username:   "alice",
		Mechanism:  credential.KindBasic,
		Outcome:    credential.OutcomeInvalid,
		StatusCode: http.StatusUnauthorized,
	}
	line := FormatEvent(event)
	if strings.Contains(line, canary) || !strings.Contains(line, "username=alice") {
		t.Fatalf("FormatEvent() = %q", line)
	}
	summary := FormatSummary(Report{StopReason: StopSuccess, Attempts: 1})
	if summary != "auth-audit: stopped reason=success attempts=1" {
		t.Fatalf("FormatSummary() = %q", summary)
	}
}

type scriptedAuth struct {
	statuses []int
	calls    atomic.Int32
}

func (auth *scriptedAuth) Verify(_ context.Context, _ model.Endpoint, secret *credential.Secret) (credential.Result, error) {
	index := int(auth.calls.Add(1) - 1)
	status := http.StatusUnauthorized
	if index < len(auth.statuses) {
		status = auth.statuses[index]
	}
	result := credential.Result{Mechanism: secret.Kind(), StatusCode: status}
	switch {
	case status >= 200 && status <= 299:
		result.Outcome = credential.OutcomeValid
		return result, nil
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		result.Outcome = credential.OutcomeInvalid
		return result, nil
	case status == http.StatusBadRequest || status == http.StatusNotFound ||
		status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented:
		result.Outcome = credential.OutcomeSecurityUnavailable
		return result, nil
	default:
		return result, fmt.Errorf("verify credential: unexpected HTTP status %d", status)
	}
}

type verifyFunc func(context.Context, model.Endpoint, *credential.Secret) (credential.Result, error)

func (fn verifyFunc) Verify(ctx context.Context, endpoint model.Endpoint, secret *credential.Secret) (credential.Result, error) {
	return fn(ctx, endpoint, secret)
}

type countingLimiter struct {
	waits atomic.Int32
}

func (limiter *countingLimiter) Wait(ctx context.Context, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	limiter.waits.Add(1)
	return nil
}

func testOptions() Options {
	options := Defaults()
	options.GlobalRate = 1000
	options.PerHostRate = 1000
	options.RetryBaseBackoff = time.Millisecond
	options.RetryMaxBackoff = time.Millisecond
	return options
}

func newTestEngine(t *testing.T, options Options, authenticator Authenticator) *Engine {
	t.Helper()
	engine, err := New(options, authenticator)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	engine.sleep = func(ctx context.Context, _ time.Duration) error {
		return ctx.Err()
	}
	return engine
}

func testEndpoint() model.Endpoint {
	return model.Endpoint{Scheme: model.SchemeHTTP, Host: "192.0.2.10", Port: 9200}
}

func mustBasic(t *testing.T, username, password string) *credential.Secret {
	t.Helper()
	secret, err := credential.NewBasic(username, []byte(password))
	if err != nil {
		t.Fatalf("NewBasic() error = %v", err)
	}
	t.Cleanup(secret.Destroy)
	return secret
}

func assertNoCanary(t *testing.T, report Report, canary string) {
	t.Helper()
	rendered := fmt.Sprintf("%+v %s %s", report, FormatSummary(report), transport.ErrorTimeout)
	for _, event := range report.Events {
		rendered += FormatEvent(event)
	}
	if strings.Contains(rendered, canary) {
		t.Fatalf("report leaked canary: %s", rendered)
	}
}
