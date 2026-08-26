package ratelimit

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestNewValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		global  float64
		perHost float64
	}{
		{0, 1},
		{math.NaN(), 1},
		{10001, 1},
		{10, 0},
		{10, math.Inf(1)},
		{10, 11},
	}
	for _, test := range tests {
		if _, err := New(test.global, test.perHost); err == nil {
			t.Fatalf("New(%v, %v) returned nil error", test.global, test.perHost)
		}
	}
}

func TestReserve(t *testing.T) {
	t.Parallel()

	now := time.Unix(100, 0)
	step := 100 * time.Millisecond
	tests := []struct {
		name          string
		next          time.Time
		wantScheduled time.Time
		wantNext      time.Time
	}{
		{"empty", time.Time{}, now, now.Add(step)},
		{"past", now.Add(-time.Second), now, now.Add(step)},
		{"future", now.Add(time.Second), now.Add(time.Second), now.Add(time.Second + step)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			scheduled, next := reserve(now, test.next, step)
			if !scheduled.Equal(test.wantScheduled) || !next.Equal(test.wantNext) {
				t.Fatalf("reserve() = %s, %s; want %s, %s", scheduled, next, test.wantScheduled, test.wantNext)
			}
		})
	}
}

func TestLimiterUsesIndependentRatesAndPrunesHosts(t *testing.T) {
	t.Parallel()

	limiter, err := New(1000, 100)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if limiter.global.step != time.Millisecond || limiter.perHostStep != 10*time.Millisecond {
		t.Fatalf("rate steps = %s global, %s per host", limiter.global.step, limiter.perHostStep)
	}
	limiter.hostNext["expired.example"] = time.Now().Add(-time.Second)
	limiter.hostReservations = hostPruneInterval - 1
	if err := limiter.Wait(context.Background(), "current.example"); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if _, exists := limiter.hostNext["expired.example"]; exists {
		t.Fatal("expired host limiter was not pruned")
	}
	if _, exists := limiter.hostNext["current.example"]; !exists {
		t.Fatal("current host limiter is missing")
	}
}

func TestLimiterCancellationAndNilReceiver(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	limiter, err := New(1, 1)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := limiter.Wait(ctx, "example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait() error = %v, want context.Canceled", err)
	}
	if err := waitUntil(ctx, time.Now().Add(time.Hour)); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitUntil() error = %v, want context.Canceled", err)
	}
	var nilLimiter *Limiter
	if err := nilLimiter.Wait(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("nil Wait() error = %v", err)
	}
}
