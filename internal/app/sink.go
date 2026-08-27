package app

import (
	"context"
	"errors"

	"github.com/cumakurt/garga/internal/capability"
	"github.com/cumakurt/garga/internal/checks"
	"github.com/cumakurt/garga/internal/fingerprint"
	"github.com/cumakurt/garga/internal/report"
	"github.com/cumakurt/garga/internal/scanner"
)

type assessmentSink struct {
	probeCtx    context.Context
	fingerprint *fingerprint.Engine
	detector    *capability.Detector
	registry    *checks.Registry
	writer      report.Writer
	findings    int
}

func (sink *assessmentSink) Write(ctx context.Context, result scanner.Result) error {
	if sink == nil || sink.fingerprint == nil || sink.registry == nil || sink.writer == nil {
		return internalError("assessment sink is not initialized", nil)
	}
	if result.Error != nil {
		return nil
	}

	identity := sink.fingerprint.Analyze(result.Probe)
	var capabilities capability.Result
	if sink.detector != nil {
		discoverCtx := sink.probeCtx
		if discoverCtx == nil {
			discoverCtx = ctx
		}
		discovered, err := sink.detector.Discover(discoverCtx, result.Endpoint, identity, result.Probe)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return err
		}
		capabilities = discovered
	}

	for _, finding := range sink.registry.Evaluate(checks.Input{
		Endpoint:     result.Endpoint,
		Fingerprint:  identity,
		Capabilities: capabilities,
	}) {
		if err := sink.writer.Write(ctx, finding); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return internalError("write finding", err)
		}
		sink.findings++
	}
	return nil
}

func (sink *assessmentSink) Close() error {
	return nil
}
