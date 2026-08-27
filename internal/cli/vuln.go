package cli

import (
	"log/slog"
	"strings"

	"github.com/cumakurt/garga/internal/app"
	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/report"
	"github.com/spf13/cobra"
)

func newVulnCommand(buildInfo BuildInfo) *cobra.Command {
	var (
		filePath     string
		format       string
		configPath   string
		signatureDir string
		insecure     bool
		concurrency  int
		rate         float64
		perHostRate  float64
		maxTargets   int
		noProgress   bool
	)

	cmd := &cobra.Command{
		Use:   "vuln [TARGET ...]",
		Short: "Match Elasticsearch versions against YAML signatures",
		Long: strings.TrimSpace(`
Probe authorized targets, fingerprint Elasticsearch, discover GET-only
capabilities, and emit potential vulnerability findings from the bundled
Elasticsearch CVE corpus (or --signatures DIR). TLS and exposure checks
are not included; use garga scan for those.

Findings stay potential: this command does not exploit, write, or confirm
a CVE. Every product request is GET. Findings do not fail the run: exit 0
means the probes finished, exit 3 means some probes failed operationally.

On a terminal, long or large scans draw a live progress bar on stderr.
Use --no-progress to disable it.

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
			return runVuln(cmd, buildInfo, vulnOptions{
				targets:      args,
				filePath:     filePath,
				format:       format,
				configPath:   configPath,
				signatureDir: signatureDir,
				insecure:     insecure,
				overrides:    overrides,
				maxTargets:   maxTargets,
				maxSet:       cmd.Flags().Changed("max-targets"),
				noProgress:   noProgress,
			})
		},
	}
	cmd.Flags().StringVar(&filePath, "file", "", "line-oriented target file, or - for stdin")
	cmd.Flags().StringVar(&format, "format", "", "output format: console, json, jsonl, csv, or html (default console)")
	cmd.Flags().StringVar(&configPath, "config", "", "optional configuration file")
	cmd.Flags().StringVar(&signatureDir, "signatures", "", "YAML signature directory (default: bundled Elasticsearch CVE corpus)")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS certificate verification")
	cmd.Flags().IntVar(&concurrency, "concurrency", config.DefaultConcurrency, "maximum concurrent root probes")
	cmd.Flags().Float64Var(&rate, "rate", config.DefaultRequestsPerSecond, "global requests per second")
	cmd.Flags().Float64Var(&perHostRate, "per-host-rate", config.DefaultPerHostRate, "per-host requests per second")
	cmd.Flags().IntVar(&maxTargets, "max-targets", app.DefaultMaxUniqueTargets, "maximum unique targets after exact deduplication")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "disable the live progress bar")
	return cmd
}

type vulnOptions struct {
	targets      []string
	filePath     string
	format       string
	configPath   string
	signatureDir string
	insecure     bool
	overrides    config.Overrides
	maxTargets   int
	maxSet       bool
	noProgress   bool
}

func runVuln(cmd *cobra.Command, buildInfo BuildInfo, options vulnOptions) error {
	if len(options.targets) == 0 && strings.TrimSpace(options.filePath) == "" {
		return &executionError{exitCode: ExitInvalidInput, message: "vuln requires a target argument or --file"}
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
	result, err := app.Vuln(cmd.Context(), app.Options{
		Config:           cfg,
		Source:           source,
		Output:           cmd.OutOrStdout(),
		Format:           format,
		Insecure:         options.insecure,
		SignatureDir:     options.signatureDir,
		Logger:           logger,
		UserAgent:        "garga/" + buildInfo.Version,
		MaxUniqueTargets: maxUnique,
		Notice:           cmd.ErrOrStderr(),
		Progress:         cmd.ErrOrStderr(),
		NoProgress:       options.noProgress,
	})
	if err != nil {
		return classifyAppError(err, "vuln failed")
	}
	logger.Debug(
		"vuln completed",
		slog.Int("findings", result.Findings),
		slog.Uint64("failed", result.Stats.Failed),
		slog.Uint64("succeeded", result.Stats.Succeeded),
	)
	if result.Stats.Failed > 0 {
		return &executionError{
			exitCode: ExitPartialFailure,
			message:  "vuln completed with partial operational failures",
		}
	}
	return nil
}
