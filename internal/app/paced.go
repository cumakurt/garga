package app

import (
	"context"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/probe"
	"github.com/cumakurt/garga/internal/ratelimit"
)

// pacedProber applies the same global and per-host rates to capability follow-up GETs.
// Root probes remain paced by the scanner engine's limiter.
type pacedProber struct {
	inner   probe.Prober
	limiter *ratelimit.Limiter
}

func (prober *pacedProber) Probe(ctx context.Context, endpoint model.Endpoint) (probe.Result, error) {
	if prober == nil || prober.inner == nil {
		return probe.Result{}, internalError("capability prober is not initialized", nil)
	}
	if prober.limiter != nil {
		if err := prober.limiter.Wait(ctx, endpoint.Host); err != nil {
			return probe.Result{}, err
		}
	}
	return prober.inner.Probe(ctx, endpoint)
}
