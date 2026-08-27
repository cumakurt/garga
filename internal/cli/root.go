package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

const (
	ExitSuccess        = 0
	ExitInternalError  = 1
	ExitInvalidInput   = 2
	ExitPartialFailure = 3
	ExitHealthError    = 4
	ExitInterrupted    = 130
)

type executionError struct {
	exitCode int
	message  string
	cause    error
}

func (err *executionError) Error() string {
	return err.message
}

func (err *executionError) Unwrap() error {
	return err.cause
}

// Execute runs the CLI with explicit arguments and streams, making command behavior testable.
func Execute(
	ctx context.Context,
	args []string,
	buildInfo BuildInfo,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) int {
	cmd := NewRootCommand(buildInfo)
	if stdin == nil {
		stdin = bytes.NewReader(nil)
	}
	cmd.SetArgs(args)
	cmd.SetIn(stdin)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	if err := cmd.ExecuteContext(ctx); err != nil {
		exitCode := ExitInvalidInput
		message := "invalid command or arguments; run 'garga --help' for usage"

		var execErr *executionError
		if errors.As(err, &execErr) {
			exitCode = execErr.exitCode
			message = execErr.message
		} else if errors.Is(err, context.Canceled) {
			exitCode = ExitInterrupted
			message = "operation interrupted"
		}

		_, _ = fmt.Fprintf(stderr, "garga: %s\n", message)
		return exitCode
	}

	return ExitSuccess
}

// NewRootCommand creates the root command without reading process-global state.
func NewRootCommand(buildInfo BuildInfo) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "garga",
		Short:         "Assess Elasticsearch security safely",
		Long:          "garga is a safe-by-default CLI for authorized Elasticsearch security assessments.",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := cmd.Help(); err != nil {
				return &executionError{
					exitCode: ExitInternalError,
					message:  "write help output",
					cause:    err,
				}
			}
			return nil
		},
	}
	cmd.CompletionOptions.DisableDefaultCmd = true
	normalized := buildInfo.normalized()
	cmd.AddCommand(newScanCommand(normalized))
	cmd.AddCommand(newFingerprintCommand(normalized))
	cmd.AddCommand(newAuthCheckCommand(normalized))
	cmd.AddCommand(newAuthAuditCommand(normalized))
	cmd.AddCommand(newVulnCommand(normalized))
	cmd.AddCommand(newHealthCommand(normalized))
	cmd.AddCommand(newReportCommand())
	cmd.AddCommand(newUpdateCommand(normalized))
	cmd.AddCommand(newVersionCommand(normalized))

	return cmd
}
