package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// BuildInfo contains version metadata injected into release binaries at link time.
type BuildInfo struct {
	Version string
	Commit  string
	BuiltAt string
}

func (info BuildInfo) normalized() BuildInfo {
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit == "" {
		info.Commit = "none"
	}
	if info.BuiltAt == "" {
		info.BuiltAt = "unknown"
	}
	return info
}

func newVersionCommand(buildInfo BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := fmt.Fprintf(
				cmd.OutOrStdout(),
				"garga %s (commit: %s, built: %s)\n",
				buildInfo.Version,
				buildInfo.Commit,
				buildInfo.BuiltAt,
			); err != nil {
				return &executionError{
					exitCode: ExitInternalError,
					message:  "write version information",
					cause:    fmt.Errorf("write version output: %w", err),
				}
			}
			return nil
		},
	}
}
