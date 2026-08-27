package cli

import (
	"log/slog"
	"strings"

	"github.com/cumakurt/garga/internal/app"
	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/report"
	"github.com/spf13/cobra"
)

func newFingerprintCommand(buildInfo BuildInfo) *cobra.Command {
	var (
		filePath    string
		format      string
		configPath  string
		insecure    bool
		concurrency int
		rate        float64
		perHostRate float64
		maxTargets  int
		threshold   int
		noProgress  bool
	)

	cmd := &cobra.Command{
		Use:   "fingerprint [TARGET ...]",
		Short: "Identify Elasticsearch with GET / probes",
		Long: strings.TrimSpace(`
Probe authorized targets with GET / and emit product identity records.
The command does not discover extra APIs, evaluate exposure checks, load
signatures, or send credentials.

Every product request is GET /. Identities do not fail the run: exit 0
means the probes finished, exit 3 means some probes failed operationally.

On a terminal, long or large scans draw a live progress bar on stderr.
Use --no-progress to disable it.

Supply targets as arguments, a --file of line-oriented hosts/CIDRs/URLs,
or both. --file - reads targets from stdin. --format accepts console,
json, or jsonl. --insecure skips TLS certificate verification only.
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
			if cmd.Flags().Changed("threshold") {
				overrides.FingerprintScore = &threshold
			}
			if cmd.Flags().Changed("format") {
				value := config.OutputFormat(format)
				overrides.OutputFormat = &value
			}
			return runFingerprint(cmd, buildInfo, fingerprintOptions{
				targets:    args,
				filePath:   filePath,
				format:     format,
				configPath: configPath,
				insecure:   insecure,
				overrides:  overrides,
				maxTargets: maxTargets,
				maxSet:     cmd.Flags().Changed("max-targets"),
				noProgress: noProgress,
			})
		},
	}
	cmd.Flags().StringVar(&filePath, "file", "", "line-oriented target file, or - for stdin")
	cmd.Flags().StringVar(&format, "format", "", "output format: console, json, or jsonl (default console)")
	cmd.Flags().StringVar(&configPath, "config", "", "optional configuration file")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS certificate verification")
	cmd.Flags().IntVar(&concurrency, "concurrency", config.DefaultConcurrency, "maximum concurrent root probes")
	cmd.Flags().Float64Var(&rate, "rate", config.DefaultRequestsPerSecond, "global requests per second")
	cmd.Flags().Float64Var(&perHostRate, "per-host-rate", config.DefaultPerHostRate, "per-host requests per second")
	cmd.Flags().IntVar(&maxTargets, "max-targets", app.DefaultMaxUniqueTargets, "maximum unique targets after exact deduplication")
	cmd.Flags().IntVar(&threshold, "threshold", config.DefaultFingerprintScore, "minimum score to mark Elasticsearch as detected")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "disable the live progress bar")
	return cmd
}

type fingerprintOptions struct {
	targets    []string
	filePath   string
	format     string
	configPath string
	insecure   bool
	overrides  config.Overrides
	maxTargets int
	maxSet     bool
	noProgress bool
}

func runFingerprint(cmd *cobra.Command, buildInfo BuildInfo, options fingerprintOptions) error {
	if len(options.targets) == 0 && strings.TrimSpace(options.filePath) == "" {
		return &executionError{exitCode: ExitInvalidInput, message: "fingerprint requires a target argument or --file"}
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
		return &executionError{exitCode: ExitInvalidInput, message: "fingerprint format is not supported", cause: err}
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
	result, err := app.Fingerprint(cmd.Context(), app.Options{
		Config:           cfg,
		Source:           source,
		Output:           cmd.OutOrStdout(),
		Format:           format,
		Insecure:         options.insecure,
		Logger:           logger,
		UserAgent:        "garga/" + buildInfo.Version,
		MaxUniqueTargets: maxUnique,
		Progress:         cmd.ErrOrStderr(),
		NoProgress:       options.noProgress,
	})
	if err != nil {
		return classifyAppError(err, "fingerprint failed")
	}
	logger.Debug(
		"fingerprint completed",
		slog.Int("identities", result.Identities),
		slog.Uint64("failed", result.Stats.Failed),
		slog.Uint64("succeeded", result.Stats.Succeeded),
	)
	if result.Stats.Failed > 0 {
		return &executionError{
			exitCode: ExitPartialFailure,
			message:  "fingerprint completed with partial operational failures",
		}
	}
	return nil
}
