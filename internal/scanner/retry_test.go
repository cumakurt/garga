package scanner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/probe"
)

func TestShouldRetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result probe.Result
		err    error
		want   bool
	}{
		{"success", probe.Result{StatusCode: 200}, nil, false},
		{"authentication required", probe.Result{StatusCode: 401}, nil, false},
		{"forbidden", probe.Result{StatusCode: 403}, nil, false},
		{"not found", probe.Result{StatusCode: 404}, nil, false},
		{"request timeout status", probe.Result{StatusCode: 408}, nil, true},
		{"too early", probe.Result{StatusCode: 425}, nil, true},
		{"rate limited", probe.Result{StatusCode: 429}, nil, true},
		{"server error", probe.Result{StatusCode: 503}, nil, true},
		{"context deadline", probe.Result{}, context.DeadlineExceeded, true},
		{"context canceled", probe.Result{}, context.Canceled, false},
		{"deterministic parse error", probe.Result{}, errors.New("parse target"), false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldRetry(test.result, test.err); got != test.want {
				t.Fatalf("shouldRetry() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestRetryDelayIsDeterministicBoundedAndExponential(t *testing.T) {
	t.Parallel()

	options := scannerTestOptions(t)
	options.RetryBaseBackoff = 100 * time.Millisecond
	options.RetryMaxBackoff = 500 * time.Millisecond
	endpoint := model.Endpoint{Scheme: model.SchemeHTTP, Host: "example.com", Port: 9200}
	first := retryDelay(options, endpoint, 1)
	if repeated := retryDelay(options, endpoint, 1); repeated != first {
		t.Fatalf("retry delay changed: %s then %s", first, repeated)
	}
	second := retryDelay(options, endpoint, 2)
	if second <= first {
		t.Fatalf("second delay %s must exceed first %s", second, first)
	}
	if capped := retryDelay(options, endpoint, 10); capped > options.RetryMaxBackoff {
		t.Fatalf("delay %s exceeds cap %s", capped, options.RetryMaxBackoff)
	}
}
