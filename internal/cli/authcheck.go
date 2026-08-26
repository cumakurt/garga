package cli

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/logging"
	"github.com/cumakurt/garga/internal/target"
	"github.com/cumakurt/garga/internal/transport"
	"github.com/spf13/cobra"
)

func newAuthCheckCommand(buildInfo BuildInfo) *cobra.Command {
	var (
		username      string
		passwordStdin bool
		apiKeyStdin   bool
		insecure      bool
		configPath    string
	)

	cmd := &cobra.Command{
		Use:   "auth-check TARGET",
		Short: "Verify one Elasticsearch credential",
		Long: strings.TrimSpace(`
Verify a single explicit Elasticsearch credential with a GET to
/_security/_authenticate.

Passwords and API keys must be supplied on stdin. garga does not accept a
--password flag because command-line secrets can appear in process listings,
shell history, and audit logs.

Use --username with --password-stdin for Basic Auth, or --api-key-stdin for an
API key. The command does not spray credentials or change cluster state.
`),
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuthCheck(cmd, buildInfo, authCheckOptions{
				target:        args[0],
				username:      username,
				passwordStdin: passwordStdin,
				apiKeyStdin:   apiKeyStdin,
				insecure:      insecure,
				configPath:    configPath,
			})
		},
	}
	cmd.Flags().StringVar(&username, "username", "", "Basic Auth username")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read the Basic Auth password from stdin")
	cmd.Flags().BoolVar(&apiKeyStdin, "api-key-stdin", false, "read the API key from stdin")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS certificate verification")
	cmd.Flags().StringVar(&configPath, "config", "", "optional configuration file")
	return cmd
}

type authCheckOptions struct {
	target        string
	username      string
	passwordStdin bool
	apiKeyStdin   bool
	insecure      bool
	configPath    string
}

func runAuthCheck(cmd *cobra.Command, buildInfo BuildInfo, options authCheckOptions) error {
	parsed, err := target.Parse(options.target, "cli")
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid target", cause: err}
	}
	endpoint, err := target.Endpoint(parsed)
	if err != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "invalid target", cause: err}
	}

	secret, err := secretFromStdin(cmd.InOrStdin(), options)
	if err != nil {
		return err
	}
	defer secret.Destroy()

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
	result, err := verifier.Verify(cmd.Context(), endpoint, secret)
	if err != nil {
		return &executionError{
			exitCode: ExitInternalError,
			message:  "credential verification failed",
			cause:    err,
		}
	}
	newLogger(cfg.Logging.Level, cmd.ErrOrStderr(), secret).Debug(
		"auth-check completed",
		logging.Bounded("outcome", string(result.Outcome), "valid", "invalid", "security_unavailable"),
		logging.Bounded("mechanism", string(result.Mechanism), string(credential.KindBasic), string(credential.KindAPIKey)),
	)
	if _, err := fmt.Fprintf(
		cmd.OutOrStdout(),
		"auth-check: %s mechanism=%s status=%d\n",
		result.Outcome,
		result.Mechanism,
		result.StatusCode,
	); err != nil {
		return &executionError{exitCode: ExitInternalError, message: "write auth-check result", cause: err}
	}
	return nil
}

func secretFromStdin(stdin io.Reader, options authCheckOptions) (*credential.Secret, error) {
	switch {
	case options.apiKeyStdin && (options.passwordStdin || options.username != ""):
		return nil, &executionError{
			exitCode: ExitInvalidInput,
			message:  "auth-check accepts either --username/--password-stdin or --api-key-stdin",
		}
	case options.apiKeyStdin:
		value, err := readSecretLine(stdin)
		if err != nil {
			return nil, err
		}
		secret, err := credential.NewAPIKey(value)
		if err != nil {
			zeroBytes(value)
			return nil, &executionError{exitCode: ExitInvalidInput, message: "invalid API key", cause: err}
		}
		return secret, nil
	case options.passwordStdin && options.username != "":
		value, err := readSecretLine(stdin)
		if err != nil {
			return nil, err
		}
		secret, err := credential.NewBasic(options.username, value)
		if err != nil {
			zeroBytes(value)
			return nil, &executionError{exitCode: ExitInvalidInput, message: "invalid Basic Auth credential", cause: err}
		}
		return secret, nil
	default:
		return nil, &executionError{
			exitCode: ExitInvalidInput,
			message:  "auth-check requires --username with --password-stdin, or --api-key-stdin",
		}
	}
}

func readSecretLine(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, &executionError{exitCode: ExitInvalidInput, message: "credential stdin is required"}
	}
	data, err := io.ReadAll(io.LimitReader(reader, credentialSecretLimit+1))
	if err != nil {
		return nil, &executionError{exitCode: ExitInternalError, message: "read credential from stdin", cause: err}
	}
	if len(data) > credentialSecretLimit {
		zeroBytes(data)
		return nil, &executionError{exitCode: ExitInvalidInput, message: "credential secret is too large"}
	}
	if index := bytes.IndexByte(data, '\n'); index >= 0 {
		zeroBytes(data[index+1:])
		data = data[:index]
	}
	data = bytes.TrimSuffix(data, []byte{'\r'})
	if len(data) == 0 {
		return nil, &executionError{exitCode: ExitInvalidInput, message: "credential secret is required on stdin"}
	}
	return data, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

const credentialSecretLimit = 4096
