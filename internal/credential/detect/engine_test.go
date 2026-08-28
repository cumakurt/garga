package detect

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
)

func TestDetectionStopsOnSuccess(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	secrets := []*credential.Secret{
		mustBasic(t, "alice", canary+"-1"),
		mustBasic(t, "bob", canary+"-2"),
	}
	auth := &scriptedAuth{statuses: []int{http.StatusUnauthorized, http.StatusOK}}
	options := testOptions(ModeStuffing)
	engine := newTestEngine(t, options, auth)

	report, err := engine.Run(context.Background(), testEndpoint(), secrets)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if auth.calls.Load() != 2 || report.StopReason != StopSuccess {
		t.Fatalf("calls=%d report=%#v", auth.calls.Load(), report)
	}
	assertNoCanary(t, report, canary)
}

func TestDetectionSprayModeRecorded(t *testing.T) {
	t.Parallel()

	secret := mustBasic(t, "alice", "credential-canary")
	options := testOptions(ModeSpraying)
	engine := newTestEngine(t, options, &scriptedAuth{statuses: []int{http.StatusUnauthorized}})

	report, err := engine.Run(context.Background(), testEndpoint(), []*credential.Secret{secret})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Mode != ModeSpraying || len(report.Events) != 1 || report.Events[0].Mode != ModeSpraying {
		t.Fatalf("report = %#v", report)
	}
}

func TestDetectionHonorsAttemptCeiling(t *testing.T) {
	t.Parallel()

	secrets := []*credential.Secret{
		mustBasic(t, "alice", "credential-canary-1"),
		mustBasic(t, "bob", "credential-canary-2"),
		mustBasic(t, "carol", "credential-canary-3"),
	}
	auth := &scriptedAuth{statuses: []int{
		http.StatusUnauthorized,
		http.StatusUnauthorized,
		http.StatusUnauthorized,
	}}
	options := testOptions(ModeDictionary)
	options.MaxAttemptsPerHost = 2
	engine := newTestEngine(t, options, auth)

	report, err := engine.Run(context.Background(), testEndpoint(), secrets)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if auth.calls.Load() != 2 || report.StopReason != StopCeiling {
		t.Fatalf("calls=%d report=%#v", auth.calls.Load(), report)
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

func testOptions(mode Mode) Options {
	options := Defaults()
	options.Mode = mode
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
	rendered := fmt.Sprintf("%+v %s", report, FormatSummary(report))
	for _, event := range report.Events {
		rendered += FormatEvent(event)
	}
	if strings.Contains(rendered, canary) {
		t.Fatalf("report leaked canary: %s", rendered)
	}
}

func TestDetectionHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secret := mustBasic(t, "alice", "credential-canary")
	engine := newTestEngine(t, testOptions(ModeBruteForce), verifyFunc(func(ctx context.Context, _ model.Endpoint, _ *credential.Secret) (credential.Result, error) {
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

type verifyFunc func(context.Context, model.Endpoint, *credential.Secret) (credential.Result, error)

func (fn verifyFunc) Verify(ctx context.Context, endpoint model.Endpoint, secret *credential.Secret) (credential.Result, error) {
	return fn(ctx, endpoint, secret)
}

func TestFormatSummaryIncludesMode(t *testing.T) {
	t.Parallel()

	summary := FormatSummary(Report{Mode: ModeSpraying, StopReason: StopCompleted, Attempts: 3, Planned: 4})
	if summary != "auth-detect: mode=spraying stopped reason=completed attempts=3 planned=4 valid=0" {
		t.Fatalf("FormatSummary() = %q", summary)
	}
}

func TestDetectionDoesNotLeakCanaryInTransportError(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	engine := newTestEngine(t, testOptions(ModeStuffing), verifyFunc(func(_ context.Context, _ model.Endpoint, _ *credential.Secret) (credential.Result, error) {
		return credential.Result{}, fmt.Errorf("dial tcp: %s", canary)
	}))

	report, err := engine.Run(context.Background(), testEndpoint(), []*credential.Secret{mustBasic(t, "alice", canary)})
	if err == nil {
		t.Fatal("Run() error = nil, want transport failure")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("error leaked canary: %v", err)
	}
	assertNoCanary(t, report, canary)
}

func TestDetectionStopsOnRateLimit(t *testing.T) {
	t.Parallel()

	secrets := []*credential.Secret{
		mustBasic(t, "alice", "credential-canary-1"),
		mustBasic(t, "bob", "credential-canary-2"),
	}
	options := testOptions(ModeSpraying)
	options.TransientRetries = 0
	auth := &scriptedAuth{statuses: []int{http.StatusTooManyRequests, http.StatusUnauthorized}}
	engine := newTestEngine(t, options, auth)

	report, err := engine.Run(context.Background(), testEndpoint(), secrets)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.StopReason != StopRateLimited || auth.calls.Load() != 1 {
		t.Fatalf("calls=%d report=%#v", auth.calls.Load(), report)
	}
}

func TestDetectionRecordsValidUsername(t *testing.T) {
	t.Parallel()

	secret := mustBasic(t, "bob", "credential-canary")
	engine := newTestEngine(t, testOptions(ModeStuffing), &scriptedAuth{statuses: []int{http.StatusOK}})

	report, err := engine.Run(context.Background(), testEndpoint(), []*credential.Secret{secret})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.StopReason != StopSuccess || len(report.ValidUsernames) != 1 || report.ValidUsernames[0] != "bob" {
		t.Fatalf("report = %#v", report)
	}
	summary := FormatSummary(report)
	if !strings.Contains(summary, "usernames=bob") || !strings.Contains(summary, "valid=1") {
		t.Fatalf("summary = %q", summary)
	}
}

func TestDetectionAddsSprayRoundDelay(t *testing.T) {
	t.Parallel()

	secrets := []*credential.Secret{
		mustBasic(t, "alice", "credential-canary-1"),
		mustBasic(t, "bob", "credential-canary-2"),
		mustBasic(t, "alice", "credential-canary-3"),
		mustBasic(t, "bob", "credential-canary-4"),
	}
	options := testOptions(ModeSpraying)
	options.SprayRoundSize = 2
	options.SprayRoundDelay = 3 * time.Second
	engine := newTestEngine(t, options, &scriptedAuth{statuses: []int{
		http.StatusUnauthorized,
		http.StatusUnauthorized,
		http.StatusUnauthorized,
		http.StatusUnauthorized,
	}})
	var delays []time.Duration
	engine.sleep = func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	}

	report, err := engine.Run(context.Background(), testEndpoint(), secrets)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.StopReason != StopCompleted || len(delays) != 3 {
		t.Fatalf("delays=%v report=%#v", delays, report)
	}
	if delays[1] < options.SprayRoundDelay {
		t.Fatalf("second delay %s missing spray round delay", delays[1])
	}
}
