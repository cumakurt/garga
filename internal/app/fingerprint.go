package app

import (
	"context"
	"errors"

	"github.com/cumakurt/garga/internal/fingerprint"
	"github.com/cumakurt/garga/internal/report"
	"github.com/cumakurt/garga/internal/scanner"
)

// Fingerprint probes targets with GET / and emits identity records. It does not
// discover capabilities, evaluate checks, or send credentials.
func Fingerprint(ctx context.Context, options Options) (result Result, err error) {
	if ctx == nil {
		return Result{}, internalError("context is required", nil)
	}
	if options.Source == nil {
		return Result{}, invalidError("fingerprint requires at least one target", nil)
	}
	if options.Output == nil {
		return Result{}, internalError("output is required", nil)
	}

	format := options.Format
	if format == "" {
		parsed, parseErr := report.ParseFormat(string(options.Config.Output.Format))
		if parseErr != nil {
			return Result{}, invalidError("fingerprint format is not supported", parseErr)
		}
		format = parsed
	}

	session, err := openProbeSession(options)
	if err != nil {
		return Result{}, err
	}
	defer session.closeIdle()
	defer session.closeProgress()

	writer, err := newIdentityWriter(format, options.Output)
	if err != nil {
		_ = session.source.Close()
		return Result{}, err
	}
	defer func() {
		session.closeProgress()
		if closeErr := writer.Close(); closeErr != nil && err == nil {
			err = internalError("write fingerprint identities", closeErr)
		}
	}()

	sink := &identitySink{
		engine: session.fingerprint,
		writer: writer,
	}
	stats, runErr := session.engine.Run(ctx, session.source, sink)
	result = Result{Stats: stats, Identities: sink.count}
	if runErr != nil {
		return result, classifyRunError(runErr)
	}
	if stats.Submitted == 0 {
		return result, invalidError("fingerprint requires at least one target", nil)
	}
	return result, nil
}

type identitySink struct {
	engine *fingerprint.Engine
	writer identityWriter
	count  int
}

func (sink *identitySink) Write(ctx context.Context, result scanner.Result) error {
	if sink == nil || sink.engine == nil || sink.writer == nil {
		return internalError("fingerprint sink is not initialized", nil)
	}
	if result.Error != nil {
		return nil
	}
	identity := newIdentity(result.Endpoint, sink.engine.Analyze(result.Probe))
	if err := sink.writer.Write(ctx, identity); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return internalError("write fingerprint identity", err)
	}
	sink.count++
	return nil
}

func (sink *identitySink) Close() error {
	return nil
}
