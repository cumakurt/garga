package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"

	"github.com/cumakurt/garga/internal/capability"
	"github.com/cumakurt/garga/internal/checks"
	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/ratelimit"
	"github.com/cumakurt/garga/internal/report"
	"github.com/cumakurt/garga/internal/scanner"
	"github.com/cumakurt/garga/internal/target"
	"github.com/cumakurt/garga/internal/vulnerability"
)

// DefaultMaxUniqueTargets is the exact-deduplication capacity for one scan.
const DefaultMaxUniqueTargets = 1_000_000

// Options configures one anonymous, GET-only assessment run.
type Options struct {
	Config           config.Config
	Source           target.Source
	Output           io.Writer
	Format           report.Format
	Insecure         bool
	SignatureDir     string
	Logger           *slog.Logger
	UserAgent        string
	MaxUniqueTargets int
}

// Result is the operational outcome of one probe run. Findings and identities
// do not fail the process.
type Result struct {
	Stats      scanner.Stats
	Findings   int
	Identities int
}

// Scan probes targets, fingerprints Elasticsearch, discovers read-only capabilities,
// evaluates checks, and streams findings. It does not verify credentials.
func Scan(ctx context.Context, options Options) (Result, error) {
	registry, err := loadRegistry(options.SignatureDir)
	if err != nil {
		if options.Source != nil {
			_ = options.Source.Close()
		}
		return Result{}, err
	}
	return assess(ctx, options, registry, "scan requires at least one target")
}

// Vuln probes targets, fingerprints Elasticsearch, discovers read-only capabilities,
// and streams signature findings only. It does not emit TLS or exposure checks.
func Vuln(ctx context.Context, options Options) (Result, error) {
	directory := strings.TrimSpace(options.SignatureDir)
	if directory == "" {
		if options.Source != nil {
			_ = options.Source.Close()
		}
		return Result{}, invalidError("vuln requires a signature directory", nil)
	}
	signatures, err := vulnerability.LoadDir(directory)
	if err != nil {
		if options.Source != nil {
			_ = options.Source.Close()
		}
		return Result{}, invalidError("invalid signature directory", err)
	}
	registry, err := checks.SignatureRegistry(signatures)
	if err != nil {
		if options.Source != nil {
			_ = options.Source.Close()
		}
		return Result{}, invalidError("invalid signature directory", err)
	}
	return assess(ctx, options, registry, "vuln requires at least one target")
}

func assess(ctx context.Context, options Options, registry *checks.Registry, emptyTargets string) (result Result, err error) {
	if ctx == nil {
		return Result{}, internalError("context is required", nil)
	}
	if options.Source == nil {
		return Result{}, invalidError(emptyTargets, nil)
	}
	if options.Output == nil {
		return Result{}, internalError("output is required", nil)
	}

	format := options.Format
	if format == "" {
		parsed, parseErr := report.ParseFormat(string(options.Config.Output.Format))
		if parseErr != nil {
			_ = options.Source.Close()
			return Result{}, invalidError("report format is not supported", parseErr)
		}
		format = parsed
	}

	session, err := openProbeSession(options)
	if err != nil {
		return Result{}, err
	}
	defer session.closeIdle()

	followUpLimiter, err := ratelimit.New(options.Config.Scanner.RequestsPerSecond, options.Config.Scanner.PerHostRate)
	if err != nil {
		_ = session.source.Close()
		return Result{}, invalidError("invalid configuration", err)
	}
	detector, err := capability.New(&pacedProber{inner: session.prober, limiter: followUpLimiter})
	if err != nil {
		_ = session.source.Close()
		return Result{}, internalError("create capability detector", err)
	}

	writer, err := report.New(format, options.Output)
	if err != nil {
		_ = session.source.Close()
		return Result{}, internalError("create report writer", err)
	}
	defer func() {
		if closeErr := writer.Close(); closeErr != nil && err == nil {
			err = internalError("write report", closeErr)
		}
	}()

	sink := &assessmentSink{
		probeCtx:    ctx,
		fingerprint: session.fingerprint,
		detector:    detector,
		registry:    registry,
		writer:      writer,
	}
	stats, runErr := session.engine.Run(ctx, session.source, sink)
	result = Result{Stats: stats, Findings: sink.findings}
	if runErr != nil {
		return result, classifyRunError(runErr)
	}
	if stats.Submitted == 0 {
		return result, invalidError(emptyTargets, nil)
	}
	return result, nil
}

func loadRegistry(signatureDir string) (*checks.Registry, error) {
	directory := strings.TrimSpace(signatureDir)
	if directory == "" {
		return checks.DefaultRegistry(), nil
	}
	signatures, err := vulnerability.LoadDir(directory)
	if err != nil {
		return nil, invalidError("invalid signature directory", err)
	}
	registry, err := checks.WithSignatures(signatures)
	if err != nil {
		return nil, invalidError("invalid signature directory", err)
	}
	return registry, nil
}

func classifyRunError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, target.ErrDeduplicationLimit) || errors.Is(err, ErrInvalidInput) {
		return invalidError("invalid target input", err)
	}
	if errors.Is(err, io.EOF) {
		return invalidError("invalid target input", err)
	}
	message := err.Error()
	if strings.Contains(message, "read scanner source:") {
		return invalidError("invalid target input", err)
	}
	if strings.Contains(message, "write scanner result:") || strings.Contains(message, "close scanner sink:") {
		return internalError("write scan results", err)
	}
	return internalError("probe run failed", err)
}
