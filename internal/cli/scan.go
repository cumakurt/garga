package cli

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/cumakurt/garga/internal/app"
	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/report"
	"github.com/spf13/cobra"
)

func newScanCommand(buildInfo BuildInfo) *cobra.Command {
	var (
		filePath     string
		format       string
		configPath   string
		signatureDir string
		insecure     bool
		noSignatures bool
		concurrency  int
		rate         float64
		perHostRate  float64
		maxTargets   int
		noProgress   bool
	)

	cmd := &cobra.Command{
		Use:   "scan [TARGET ...]",
		Short: "Run a read-only Elasticsearch security assessment",
		Long: strings.TrimSpace(`
Probe authorized targets, fingerprint Elasticsearch, discover GET-only
capabilities, and emit exposure findings plus potential CVE matches from
the bundled Elasticsearch signature corpus. Override the corpus with
--signatures DIR, or disable CVE matching with --no-signatures.

The command does not send credentials, does not spray passwords, and does
not change cluster state. Every product request is GET. Findings do not
fail the run: exit 0 means the scan finished, exit 3 means some probes
failed operationally. CVE hits stay potential: version evidence is not
confirmed exploitation.

On a terminal, long or large scans draw a live progress bar on stderr.
Use --no-progress to disable it. Findings stay on stdout.

Supply targets as arguments, a --file of line-oriented hosts/CIDRs/URLs,
or both. --file - reads targets from stdin. --insecure skips TLS
certificate verification only.
`),
		Args:          cobra.ArbitraryArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			overrides := config.Overrides{}
			if cmd.Flags().Changed("concurrency") {
				overrides.Concurrency = &concurrency
			}
			if cmd.Flags().Changed("rate") {
				overrides.RequestsPerSecond = &rate
			}
			if cmd.Flags().Changed("per-host-rate") {
				overrides.PerHostRate = &perHostRate
			}
			if cmd.Flags().Changed("format") {
				value := config.OutputFormat(format)
				overrides.OutputFormat = &value
			}
			return runScan(cmd, buildInfo, scanOptions{
				targets:        args,
				filePath:       filePath,
				format:         format,
				configPath:     configPath,
				signatureDir:   signatureDir,
				insecure:       insecure,
				skipSignatures: noSignatures,
				overrides:      overrides,
				maxTargets:     maxTargets,
				maxSet:         cmd.Flags().Changed("max-targets"),
				noProgress:     noProgress,
			})
		},
	}
	cmd.Flags().StringVar(&filePath, "file", "", "line-oriented target file, or - for stdin")
	cmd.Flags().StringVar(&format, "format", "", "output format: console, json, jsonl, csv, or html (default console)")
	cmd.Flags().StringVar(&configPath, "config", "", "optional configuration file")
	cmd.Flags().StringVar(&signatureDir, "signatures", "", "YAML signature directory (default: bundled Elasticsearch CVE corpus)")
	cmd.Flags().BoolVar(&noSignatures, "no-signatures", false, "skip vulnerability signature matching")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS certificate verification")
	cmd.Flags().IntVar(&concurrency, "concurrency", config.DefaultConcurrency, "maximum concurrent root probes")
	cmd.Flags().Float64Var(&rate, "rate", config.DefaultRequestsPerSecond, "global requests per second")
	cmd.Flags().Float64Var(&perHostRate, "per-host-rate", config.DefaultPerHostRate, "per-host requests per second")
	cmd.Flags().IntVar(&maxTargets, "max-targets", app.DefaultMaxUniqueTargets, "maximum unique targets after exact deduplication")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "disable the live progress bar")
	return cmd
}

type scanOptions struct {
	targets        []string
	filePath       string
	format         string
	configPath     string
	signatureDir   string
	insecure       bool
	skipSignatures bool
	overrides      config.Overrides
	maxTargets     int
	maxSet         bool
	noProgress     bool
}

func runScan(cmd *cobra.Command, buildInfo BuildInfo, options scanOptions) error {
	if options.skipSignatures && strings.TrimSpace(options.signatureDir) != "" {
		return &executionError{exitCode: ExitInvalidInput, message: "--no-signatures cannot be combined with --signatures"}
	}
	if len(options.targets) == 0 && strings.TrimSpace(options.filePath) == "" {
		return &executionError{exitCode: ExitInvalidInput, message: "scan requires a target argument or --file"}
	}

	cfg, err := config.Load(config.Options{ConfigPath: options.configPath, Overrides: options.overrides})
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid configuration", cause: err}
	}
	formatValue := options.format
	if formatValue == "" {
		formatValue = string(cfg.Output.Format)
	}
	format, err := report.ParseFormat(formatValue)
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "report format is not supported", cause: err}
	}

	if options.maxSet && options.maxTargets <= 0 {
		return &executionError{exitCode: ExitInvalidInput, message: "max-targets must be positive"}
	}

	source, err := openTargetSource(options.targets, options.filePath, cmd.InOrStdin())
	if err != nil {
		return err
	}

	maxUnique := 0
	if options.maxSet {
		maxUnique = options.maxTargets
	}

	logger := newLogger(cfg.Logging.Level, cmd.ErrOrStderr())
	result, err := app.Scan(cmd.Context(), app.Options{
		Config:           cfg,
		Source:           source,
		Output:           cmd.OutOrStdout(),
		Format:           format,
		Insecure:         options.insecure,
		SignatureDir:     options.signatureDir,
		SkipSignatures:   options.skipSignatures,
		Logger:           logger,
		UserAgent:        "garga/" + buildInfo.Version,
		MaxUniqueTargets: maxUnique,
		Notice:           cmd.ErrOrStderr(),
		Progress:         cmd.ErrOrStderr(),
		NoProgress:       options.noProgress,
	})
	if err != nil {
		return classifyAppError(err, "scan failed")
	}
	logger.Debug(
		"scan completed",
		slog.Int("findings", result.Findings),
		slog.Uint64("failed", result.Stats.Failed),
		slog.Uint64("succeeded", result.Stats.Succeeded),
	)
	if result.Stats.Failed > 0 {
		return &executionError{
			exitCode: ExitPartialFailure,
			message:  "scan completed with partial operational failures",
		}
	}
	return nil
}

func classifyAppError(err error, fallback string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, app.ErrInvalidInput) {
		return &executionError{exitCode: ExitInvalidInput, message: err.Error(), cause: err}
	}
	message := fallback
	var appErr *app.Error
	if errors.As(err, &appErr) && appErr.Error() != "" {
		message = appErr.Error()
	}
	return &executionError{exitCode: ExitInternalError, message: message, cause: err}
}
