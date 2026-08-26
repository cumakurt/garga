package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/transport"
	"github.com/cumakurt/garga/internal/update"
	"github.com/spf13/cobra"
	"log/slog"
)

const ExitUpdateFailure = 4

func newUpdateCommand(buildInfo BuildInfo) *cobra.Command {
	var (
		source     string
		dir        string
		rollback   bool
		insecure   bool
		configPath string
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Install a signed vulnerability signature database",
		Long: strings.TrimSpace(`
Fetch a signed signature bundle, verify it against the embedded Ed25519 trust
root, extract it into a staging directory, validate every YAML signature, and
activate it atomically. Interrupted or invalid updates leave the active
database unchanged.

--source is a local directory or an HTTP(S) directory URL containing
manifest.json, manifest.sig, and signatures.zip. --dir is the signature
database directory (current/ and previous/). Use --rollback to restore the
previous database.
`),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUpdate(cmd, buildInfo, updateOptions{
				source:     source,
				dir:        dir,
				rollback:   rollback,
				insecure:   insecure,
				configPath: configPath,
			})
		},
	}
	cmd.Flags().StringVar(&source, "source", "", "bundle directory or HTTP(S) directory URL")
	cmd.Flags().StringVar(&dir, "dir", "", "signature database directory")
	cmd.Flags().BoolVar(&rollback, "rollback", false, "restore the previous signature database")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS certificate verification")
	cmd.Flags().StringVar(&configPath, "config", "", "optional configuration file")
	return cmd
}

type updateOptions struct {
	source     string
	dir        string
	rollback   bool
	insecure   bool
	configPath string
}

func runUpdate(cmd *cobra.Command, buildInfo BuildInfo, options updateOptions) error {
	if options.dir == "" {
		return &executionError{exitCode: ExitInvalidInput, message: "update requires --dir"}
	}
	if options.rollback && options.source != "" {
		return &executionError{exitCode: ExitInvalidInput, message: "update --rollback does not accept --source"}
	}
	if options.rollback {
		if err := update.Rollback(options.dir); err != nil {
			return classifyUpdateError(err)
		}
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "update: restored previous signature database"); err != nil {
			return &executionError{exitCode: ExitInternalError, message: "write update result", cause: err}
		}
		return nil
	}
	if options.source == "" {
		return &executionError{exitCode: ExitInvalidInput, message: "update requires --source"}
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
	transportOptions.MaxResponseBytes = update.MaxArchiveBytes
	factory, err := transport.NewFactory(transportOptions)
	if err != nil {
		return &executionError{exitCode: ExitInternalError, message: "create HTTP transport", cause: err}
	}
	defer factory.CloseIdleConnections()

	result, err := update.Apply(cmd.Context(), update.Options{
		Source: options.source,
		Dir:    options.dir,
		Client: factory.Client(),
	})
	if err != nil {
		return classifyUpdateError(err)
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "update: activated %s (%d signatures)\n", result.Version, result.Files); err != nil {
		return &executionError{exitCode: ExitInternalError, message: "write update result", cause: err}
	}
	newLogger(cfg.Logging.Level, cmd.ErrOrStderr()).Info(
		"signature update activated",
		slog.Int("files", result.Files),
	)
	return nil
}

func classifyUpdateError(err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	switch {
	case errors.Is(err, update.ErrVerification), errors.Is(err, update.ErrArchive), errors.Is(err, update.ErrValidation), errors.Is(err, update.ErrFetch):
		return &executionError{exitCode: ExitUpdateFailure, message: err.Error(), cause: err}
	default:
		if _, ok := transport.KindOf(err); ok {
			return &executionError{exitCode: ExitInternalError, message: "signature update request failed", cause: err}
		}
		return &executionError{exitCode: ExitInternalError, message: "signature update failed", cause: err}
	}
}
