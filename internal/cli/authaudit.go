package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/credential/audit"
	"github.com/cumakurt/garga/internal/logging"
	"github.com/cumakurt/garga/internal/target"
	"github.com/cumakurt/garga/internal/transport"
	"github.com/spf13/cobra"
	"log/slog"
)

func newAuthAuditCommand(buildInfo BuildInfo) *cobra.Command {
	var (
		credentialsStdin bool
		insecure         bool
		configPath       string
		maxAttempts      int
	)

	cmd := &cobra.Command{
		Use:   "auth-audit TARGET",
		Short: "Run an explicit, bounded credential audit",
		Long: strings.TrimSpace(`
Run an isolated, opt-in credential audit against one Elasticsearch target.

This command is not part of the normal scan path and does not spray credentials
implicitly. Supply an explicit list on stdin with --credentials-stdin. garga
does not accept a --password flag because command-line secrets can appear in
process listings, shell history, and audit logs.

Each attempt is a GET to /_security/_authenticate. The engine stops on the
first valid credential or when Elasticsearch security is unavailable. A per-host
attempt ceiling and a 1 request/second default rate apply to every request,
including retries. Cancellation is honored end-to-end.

Credential lines:

  basic USERNAME PASSWORD
  api_key KEY
`),
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuthAudit(cmd, buildInfo, authAuditOptions{
				target:           args[0],
				credentialsStdin: credentialsStdin,
				insecure:         insecure,
				configPath:       configPath,
				maxAttempts:      maxAttempts,
			})
		},
	}
	cmd.Flags().BoolVar(&credentialsStdin, "credentials-stdin", false, "read the credential list from stdin")
	cmd.Flags().IntVar(&maxAttempts, "max-attempts", audit.DefaultMaxAttemptsPerHost, "maximum authenticate requests per host")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS certificate verification")
	cmd.Flags().StringVar(&configPath, "config", "", "optional configuration file")
	return cmd
}

type authAuditOptions struct {
	target           string
	credentialsStdin bool
	insecure         bool
	configPath       string
	maxAttempts      int
}

func runAuthAudit(cmd *cobra.Command, buildInfo BuildInfo, options authAuditOptions) error {
	if !options.credentialsStdin {
		return &executionError{
			exitCode: ExitInvalidInput,
			message:  "auth-audit requires --credentials-stdin",
		}
	}

	parsed, err := target.Parse(options.target, "cli")
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid target", cause: err}
	}
	endpoint, err := target.Endpoint(parsed)
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid target", cause: err}
	}

	secrets, err := audit.ParseCredentials(cmd.InOrStdin())
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid credential list", cause: err}
	}
	defer destroySecrets(secrets)

	auditOptions := audit.Defaults()
	auditOptions.MaxAttemptsPerHost = options.maxAttempts
	if err := auditOptions.Validate(); err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid credential audit options", cause: err}
	}

	cfg, err := config.Load(config.Options{ConfigPath: options.configPath})
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid configuration", cause: err}
	}
	transportOptions, err := transport.OptionsFromConfig(cfg, "garga/"+buildInfo.Version)
	if err != nil {
		return &executionError{exitCode: ExitInternalError, message: "invalid transport options", cause: err}
	}
	transportOptions.InsecureSkipVerify = options.insecure
	factory, err := transport.NewFactory(transportOptions)
	if err != nil {
		return &executionError{exitCode: ExitInternalError, message: "create HTTP transport", cause: err}
	}
	defer factory.CloseIdleConnections()

	verifier, err := credential.NewVerifier(factory.Client())
	if err != nil {
		return &executionError{exitCode: ExitInternalError, message: "create credential verifier", cause: err}
	}
	engine, err := audit.New(auditOptions, verifier)
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid credential audit options", cause: err}
	}

	report, err := engine.Run(cmd.Context(), endpoint, secrets)
	if writeErr := writeAuditReport(cmd.OutOrStdout(), report, secrets); writeErr != nil {
		return &executionError{exitCode: ExitInternalError, message: "write auth-audit result", cause: writeErr}
	}
	if err != nil {
		if cmd.Context().Err() != nil {
			return cmd.Context().Err()
		}
		return &executionError{exitCode: ExitInternalError, message: "credential audit failed", cause: err}
	}
	newLogger(cfg.Logging.Level, cmd.ErrOrStderr(), secrets...).Debug(
		"auth-audit completed",
		logging.Bounded("stop_reason", string(report.StopReason),
			string(audit.StopCompleted),
			string(audit.StopSuccess),
			string(audit.StopCeiling),
			string(audit.StopUnavailable),
			string(audit.StopCanceled),
		),
		slog.Int("attempts", report.Attempts),
	)
	return nil
}

func writeAuditReport(stdout io.Writer, report audit.Report, secrets []*credential.Secret) error {
	for _, event := range report.Events {
		line := redactAuditText(audit.FormatEvent(event), secrets)
		if _, err := fmt.Fprintln(stdout, line); err != nil {
			return err
		}
	}
	if report.StopReason == "" {
		return nil
	}
	_, err := fmt.Fprintln(stdout, redactAuditText(audit.FormatSummary(report), secrets))
	return err
}

func redactAuditText(text string, secrets []*credential.Secret) string {
	for _, secret := range secrets {
		text = credential.Redact(text, secret)
	}
	return text
}

func destroySecrets(secrets []*credential.Secret) {
	for _, secret := range secrets {
		secret.Destroy()
	}
}
