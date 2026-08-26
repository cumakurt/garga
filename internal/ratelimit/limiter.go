package ratelimit

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

const (
	hostPruneInterval = 128
	maxRate           = 10_000.0
)

// Limiter applies one global pacer and one independently scheduled pacer per host.
type Limiter struct {
	global      pacer
	perHostStep time.Duration

	hostMu           sync.Mutex
	hostNext         map[string]time.Time
	hostReservations uint64
}

type pacer struct {
	mu   sync.Mutex
	next time.Time
	step time.Duration
}

// New validates rates and creates a goroutine-free shared request limiter.
func New(globalRate, perHostRate float64) (*Limiter, error) {
	if invalidRate(globalRate) {
		return nil, fmt.Errorf("create request limiter: global rate must be greater than zero and at most %g", maxRate)
	}
	if invalidRate(perHostRate) || perHostRate > globalRate {
		return nil, fmt.Errorf("create request limiter: per-host rate must be greater than zero, at most %g, and no greater than the global rate", maxRate)
	}
	return &Limiter{
		global:      pacer{step: rateInterval(globalRate)},
		perHostStep: rateInterval(perHostRate),
		hostNext:    make(map[string]time.Time),
	}, nil
}

// Wait reserves one global and per-host request slot or returns on cancellation.
func (limiter *Limiter) Wait(ctx context.Context, host string) error {
	if limiter == nil {
		return fmt.Errorf("wait for request limit: limiter is not initialized")
	}
	if err := limiter.global.wait(ctx); err != nil {
		return err
	}

	now := time.Now()
	limiter.hostMu.Lock()
	limiter.hostReservations++
	if limiter.hostReservations%hostPruneInterval == 0 {
		for key, next := range limiter.hostNext {
			if !next.After(now) {
				delete(limiter.hostNext, key)
			}
		}
	}
	scheduled, next := reserve(now, limiter.hostNext[host], limiter.perHostStep)
	limiter.hostNext[host] = next
	limiter.hostMu.Unlock()

	return waitUntil(ctx, scheduled)
}

func (limiter *pacer) wait(ctx context.Context) error {
	now := time.Now()
	limiter.mu.Lock()
	scheduled, next := reserve(now, limiter.next, limiter.step)
	limiter.next = next
	limiter.mu.Unlock()
	return waitUntil(ctx, scheduled)
}

func invalidRate(value float64) bool {
	return math.IsNaN(value) || math.IsInf(value, 0) || value <= 0 || value > maxRate
}

func rateInterval(rate float64) time.Duration {
	return time.Duration(float64(time.Second) / rate)
}

func reserve(now, next time.Time, step time.Duration) (time.Time, time.Time) {
	scheduled := now
	if next.After(now) {
		scheduled = next
	}
	return scheduled, scheduled.Add(step)
}

func waitUntil(ctx context.Context, scheduled time.Time) error {
	delay := time.Until(scheduled)
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
