package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/health"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
	healthreport "github.com/cumakurt/garga/internal/health/report"
	"github.com/cumakurt/garga/internal/target"
	"github.com/spf13/cobra"
)

const defaultHealthTimeout = 2 * time.Minute

func newHealthCommand(buildInfo BuildInfo) *cobra.Command {
	var options healthCLIOptions
	cmd := &cobra.Command{
		Use:   "health TARGET",
		Short: "Run an advanced read-only Elasticsearch health assessment",
		Long: strings.TrimSpace(`
Collect a bounded Elasticsearch cluster snapshot through GET-only APIs, normalize it,
evaluate independent health checkers, correlate root causes, calculate a weighted score,
and produce actionable operational findings.

The default scan uses low/medium-cost APIs. --deep enables ILM, data stream, task,
node-security-setting, and snapshot analysis. No index, setting, policy, shard, or
cluster state is changed. Partial API failures are reported and other checks continue.

Credentials are optional. Prefer --username with --password-stdin, --api-key-stdin,
or --bearer-token-stdin. ESHEALTH_USERNAME, ESHEALTH_PASSWORD, ESHEALTH_API_KEY,
and ESHEALTH_BEARER_TOKEN are supported for automation but are less private than stdin.
Credentials are never written to logs or reports. Sending credentials over HTTP is
refused unless --allow-plaintext-auth is explicitly set.

Every completed assessment writes a timestamped standalone PDF report to the
current directory and prints its path on stderr. Pass --html-report to also
write the HTML health report.
`),
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			options.target = args[0]
			options.profileSet = cmd.Flags().Changed("profile")
			options.concurrencySet = cmd.Flags().Changed("concurrency")
			options.rateSet = cmd.Flags().Changed("requests-per-second")
			options.topNSet = cmd.Flags().Changed("top-n")
			options.maxResponseBytesSet = cmd.Flags().Changed("max-response-bytes")
			options.requestTimeoutSet = cmd.Flags().Changed("request-timeout")
			options.htmlReportSet = cmd.Flags().Changed("html-report")
			return runHealth(cmd, buildInfo, options)
		},
	}
	cmd.Flags().StringVar(&options.configPath, "config", "", "optional configuration file")
	cmd.Flags().StringVar(&options.profile, "profile", string(config.HealthProfileStandard), "health profile: development, small, standard, large, logging, search, security, or production")
	cmd.Flags().BoolVar(&options.deep, "deep", false, "enable higher-cost ILM, task, snapshot, data stream, and security-setting collectors")
	cmd.Flags().StringVar(&options.format, "format", string(healthreport.FormatTerminal), "output format: terminal, json, html, or markdown")
	cmd.Flags().DurationVar(&options.timeout, "timeout", defaultHealthTimeout, "overall health assessment timeout")
	cmd.Flags().DurationVar(&options.requestTimeout, "request-timeout", config.DefaultRequestTimeout, "timeout for each Elasticsearch request")
	cmd.Flags().IntVar(&options.concurrency, "concurrency", config.DefaultHealthConcurrency, "maximum concurrent Elasticsearch health requests")
	cmd.Flags().Float64Var(&options.rate, "requests-per-second", config.DefaultHealthRate, "maximum Elasticsearch health requests per second")
	cmd.Flags().IntVar(&options.topN, "top-n", config.DefaultHealthTopN, "number of top risks and resource consumers")
	cmd.Flags().Int64Var(&options.maxResponseBytes, "max-response-bytes", config.DefaultHealthMaxResponse, "maximum Elasticsearch response body size in bytes")
	cmd.Flags().StringVar(&options.failOn, "fail-on", "", "exit 10/11/12 when findings reach warning, high, or critical")
	cmd.Flags().StringVar(&options.baselinePath, "baseline", "", "baseline JSON file for cumulative-counter delta analysis")
	cmd.Flags().StringVar(&options.snapshotOut, "snapshot-out", "", "save a secret-free counter baseline JSON file")
	cmd.Flags().BoolVar(&options.overwriteSnapshot, "force", false, "replace an existing --snapshot-out file")
	cmd.Flags().StringVar(&options.username, "username", "", "Basic Auth username")
	cmd.Flags().BoolVar(&options.passwordStdin, "password-stdin", false, "read the Basic Auth password from stdin")
	cmd.Flags().BoolVar(&options.apiKeyStdin, "api-key-stdin", false, "read the API key from stdin")
	cmd.Flags().BoolVar(&options.bearerStdin, "bearer-token-stdin", false, "read a Bearer token from stdin")
	cmd.Flags().BoolVar(&options.allowPlaintextAuth, "allow-plaintext-auth", false, "allow credentials over HTTP (unsafe; reported as CRITICAL)")
	cmd.Flags().BoolVar(&options.insecure, "insecure", false, "skip TLS certificate verification")
	cmd.Flags().BoolVar(&options.debug, "debug", false, "enable redacted structured debug logs on stderr")
	cmd.Flags().BoolVar(&options.htmlReport, "html-report", false, "also write the timestamped HTML health report")
	return cmd
}

type healthCLIOptions struct {
	target, configPath, profile, format, failOn, baselinePath, snapshotOut, username                    string
	deep, overwriteSnapshot, passwordStdin, apiKeyStdin, bearerStdin                                    bool
	allowPlaintextAuth, insecure, debug                                                                 bool
	timeout, requestTimeout                                                                             time.Duration
	concurrency, topN                                                                                   int
	maxResponseBytes                                                                                    int64
	rate                                                                                                float64
	profileSet, concurrencySet, rateSet, topNSet, maxResponseBytesSet, requestTimeoutSet, htmlReportSet bool
	htmlReport                                                                                          bool
}

func runHealth(cmd *cobra.Command, buildInfo BuildInfo, options healthCLIOptions) error {
	if options.timeout <= 0 || options.timeout > 24*time.Hour {
		return healthInputError("health timeout must be greater than 0 and at most 24h", nil)
	}
	if options.overwriteSnapshot && strings.TrimSpace(options.snapshotOut) == "" {
		return healthInputError("--force requires --snapshot-out", nil)
	}
	parsedTarget, err := target.Parse(options.target, "cli")
	if err != nil {
		return healthInputError("invalid health target", err)
	}
	endpoint, err := target.Endpoint(parsedTarget)
	if err != nil {
		return healthInputError("invalid health target", err)
	}

	secret, err := healthSecret(cmd, options)
	if err != nil {
		return err
	}
	if secret != nil {
		defer secret.Destroy()
	}

	overrides := config.Overrides{}
	if options.profileSet {
		profile := config.HealthProfile(options.profile)
		overrides.HealthProfile = &profile
	}
	if options.concurrencySet {
		overrides.HealthConcurrency = &options.concurrency
	}
	if options.rateSet {
		overrides.HealthRate = &options.rate
	}
	if options.topNSet {
		overrides.HealthTopN = &options.topN
	}
	if options.maxResponseBytesSet {
		overrides.HealthMaxResponseBytes = &options.maxResponseBytes
	}
	if options.requestTimeoutSet {
		overrides.RequestTimeout = &options.requestTimeout
		connectTimeout := options.requestTimeout
		if connectTimeout > config.DefaultConnectTimeout {
			connectTimeout = config.DefaultConnectTimeout
		}
		overrides.ConnectTimeout = &connectTimeout
	}
	if options.debug {
		level := config.LogDebug
		overrides.LogLevel = &level
	}
	if options.htmlReportSet {
		overrides.HTMLReport = &options.htmlReport
	}
	cfg, err := config.Load(config.Options{ConfigPath: options.configPath, Overrides: overrides})
	if err != nil {
		return healthInputError("invalid health configuration", err)
	}
	format, err := healthreport.ParseFormat(options.format)
	if err != nil {
		return healthInputError("health report format is not supported", err)
	}
	failOn, err := parseFailOn(options.failOn)
	if err != nil {
		return healthInputError("invalid --fail-on severity", err)
	}
	var baseline *healthmodel.Baseline
	if strings.TrimSpace(options.baselinePath) != "" {
		baseline, err = health.LoadBaseline(options.baselinePath)
		if err != nil {
			return healthInputError("invalid health baseline", err)
		}
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), options.timeout)
	defer cancel()
	logger := newLogger(cfg.Logging.Level, cmd.ErrOrStderr(), secret)
	result, err := health.Run(ctx, health.Options{
		Config: cfg, Endpoint: endpoint, Secret: secret, Deep: options.deep, Insecure: options.insecure,
		AllowPlaintextAuth: options.allowPlaintextAuth, UserAgent: "garga/" + buildInfo.Version, ScannerVersion: buildInfo.Version,
		Baseline: baseline, Logger: logger,
	})
	if err != nil {
		return classifyHealthError(err)
	}
	if options.snapshotOut != "" {
		if err := health.SaveBaseline(options.snapshotOut, result.Baseline, options.overwriteSnapshot); err != nil {
			return &executionError{exitCode: ExitInternalError, message: "save health baseline failed", cause: err}
		}
	}
	artifactPath, err := healthreport.WriteTimestampedPDF(result.Report)
	if err != nil {
		return &executionError{exitCode: ExitInternalError, message: "write timestamped health PDF report", cause: err}
	}
	if err := healthreport.Write(cmd.OutOrStdout(), format, result.Report); err != nil {
		return &executionError{exitCode: ExitInternalError, message: "write health report", cause: err}
	}
	if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "garga: PDF health report written to %s\n", artifactPath); err != nil {
		return &executionError{exitCode: ExitInternalError, message: "write health report notice", cause: err}
	}
	if cfg.Output.HTMLReport {
		htmlPath, htmlErr := healthreport.WriteTimestampedHTML(result.Report)
		if htmlErr != nil {
			return &executionError{exitCode: ExitInternalError, message: "write timestamped health HTML report", cause: htmlErr}
		}
		if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "garga: HTML health report written to %s\n", htmlPath); err != nil {
			return &executionError{exitCode: ExitInternalError, message: "write health report notice", cause: err}
		}
	}
	if failOn != "" {
		if code, severity := healthFailureCode(result.Report.Findings, failOn); code != 0 {
			return &executionError{exitCode: code, message: "health assessment completed at " + string(severity) + " severity"}
		}
	}
	return nil
}

func healthSecret(cmd *cobra.Command, options healthCLIOptions) (*credential.Secret, error) {
	mechanisms := 0
	for _, enabled := range []bool{options.passwordStdin, options.apiKeyStdin, options.bearerStdin} {
		if enabled {
			mechanisms++
		}
	}
	if mechanisms > 1 {
		return nil, healthInputError("select only one health authentication mechanism", nil)
	}
	username := strings.TrimSpace(options.username)
	if username == "" {
		username = strings.TrimSpace(os.Getenv("ESHEALTH_USERNAME"))
	}
	if mechanisms == 1 {
		value, err := readSecretLine(cmd.InOrStdin())
		if err != nil {
			return nil, healthInputError("read health credential from stdin", err)
		}
		switch {
		case options.passwordStdin:
			if username == "" {
				zeroBytes(value)
				return nil, healthInputError("--password-stdin requires --username or ESHEALTH_USERNAME", nil)
			}
			secret, createErr := credential.NewBasic(username, value)
			if createErr != nil {
				return nil, healthInputError("invalid Basic Auth credential", createErr)
			}
			return secret, nil
		case options.apiKeyStdin:
			secret, createErr := credential.NewAPIKey(value)
			if createErr != nil {
				return nil, healthInputError("invalid API key", createErr)
			}
			return secret, nil
		default:
			secret, createErr := credential.NewBearer(value)
			if createErr != nil {
				return nil, healthInputError("invalid Bearer token", createErr)
			}
			return secret, nil
		}
	}
	environment := []struct {
		name string
		kind credential.Kind
	}{{"ESHEALTH_PASSWORD", credential.KindBasic}, {"ESHEALTH_API_KEY", credential.KindAPIKey}, {"ESHEALTH_BEARER_TOKEN", credential.KindBearer}}
	selectedValue, selectedKind := "", credential.Kind("")
	for _, candidate := range environment {
		if value, present := os.LookupEnv(candidate.name); present && value != "" {
			if selectedKind != "" {
				return nil, healthInputError("multiple ESHEALTH credential variables are set", nil)
			}
			selectedValue, selectedKind = value, candidate.kind
		}
	}
	if selectedKind == "" {
		if username != "" {
			return nil, healthInputError("a Basic Auth username requires --password-stdin or ESHEALTH_PASSWORD", nil)
		}
		return nil, nil
	}
	value := []byte(selectedValue)
	switch selectedKind {
	case credential.KindBasic:
		if username == "" {
			zeroBytes(value)
			return nil, healthInputError("ESHEALTH_PASSWORD requires --username or ESHEALTH_USERNAME", nil)
		}
		secret, createErr := credential.NewBasic(username, value)
		if createErr != nil {
			return nil, healthInputError("invalid Basic Auth credential", createErr)
		}
		return secret, nil
	case credential.KindAPIKey:
		secret, createErr := credential.NewAPIKey(value)
		if createErr != nil {
			return nil, healthInputError("invalid API key", createErr)
		}
		return secret, nil
	default:
		secret, createErr := credential.NewBearer(value)
		if createErr != nil {
			return nil, healthInputError("invalid Bearer token", createErr)
		}
		return secret, nil
	}
}

func parseFailOn(value string) (healthmodel.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", nil
	case "warning", "medium":
		return healthmodel.SeverityMedium, nil
	case "high":
		return healthmodel.SeverityHigh, nil
	case "critical":
		return healthmodel.SeverityCritical, nil
	default:
		return "", fmt.Errorf("expected warning, high, or critical")
	}
}

func healthFailureCode(findings []healthmodel.Finding, threshold healthmodel.Severity) (int, healthmodel.Severity) {
	highest := healthmodel.SeverityOK
	for _, finding := range findings {
		if healthmodel.SeverityRank(finding.Severity) > healthmodel.SeverityRank(highest) {
			highest = finding.Severity
		}
	}
	if healthmodel.SeverityRank(highest) < healthmodel.SeverityRank(threshold) {
		return 0, highest
	}
	switch highest {
	case healthmodel.SeverityCritical:
		return ExitHealthCritical, highest
	case healthmodel.SeverityHigh:
		return ExitHealthHigh, highest
	default:
		return ExitHealthWarning, highest
	}
}

func classifyHealthError(err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return healthOperationalError("health assessment timed out", err)
	}
	var healthError *health.Error
	if errors.As(err, &healthError) {
		if healthError.Kind == health.ErrorConfiguration {
			return healthInputError(healthError.Error(), err)
		}
		return healthOperationalError(healthError.Error(), err)
	}
	return healthOperationalError("health assessment failed", err)
}

func healthInputError(message string, cause error) error {
	return &executionError{exitCode: ExitInvalidInput, message: message, cause: cause}
}

func healthOperationalError(message string, cause error) error {
	return &executionError{exitCode: ExitHealthFailure, message: message, cause: cause}
}
