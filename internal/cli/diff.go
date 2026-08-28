package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cumakurt/garga/internal/lifecycle"
	"github.com/spf13/cobra"
)

func newDiffCommand() *cobra.Command {
	var (
		baselinePath string
		currentPath  string
		formatValue  string
		failOn       string
	)
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare finding lifecycle between two JSONL assessments",
		Long: strings.TrimSpace(`
Compare baseline and current JSONL findings without contacting the network.
Findings are correlated by their stable ID and classified as new, resolved,
unchanged, regressed, or improved. Risk changes include severity,
applicability, CISA KEV status, and priority score.
`),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDiff(cmd, baselinePath, currentPath, formatValue, failOn)
		},
	}
	cmd.Flags().StringVar(&baselinePath, "baseline", "", "baseline JSONL findings file, or - for stdin")
	cmd.Flags().StringVar(&currentPath, "current", "", "current JSONL findings file, or - for stdin")
	cmd.Flags().StringVar(&formatValue, "format", string(lifecycle.FormatConsole), "output format: console, json, or jsonl")
	cmd.Flags().StringVar(&failOn, "fail-on", "none", "return exit code 3 on: none, new, regressed, or any-change")
	return cmd
}

func runDiff(cmd *cobra.Command, baselinePath, currentPath, formatValue, failOn string) (err error) {
	if strings.TrimSpace(baselinePath) == "" || strings.TrimSpace(currentPath) == "" {
		return &executionError{exitCode: ExitInvalidInput, message: "diff requires --baseline and --current"}
	}
	if baselinePath == "-" && currentPath == "-" {
		return &executionError{exitCode: ExitInvalidInput, message: "only one diff input may use stdin"}
	}
	format, parseErr := lifecycle.ParseFormat(formatValue)
	if parseErr != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "diff format is not supported", cause: parseErr}
	}
	failOn = strings.ToLower(strings.TrimSpace(failOn))
	switch failOn {
	case "none", "new", "regressed", "any-change":
	default:
		return &executionError{exitCode: ExitInvalidInput, message: "diff fail-on must be none, new, regressed, or any-change"}
	}

	baseline, closeBaseline, openErr := openDiffInput(baselinePath, cmd.InOrStdin())
	if openErr != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "open diff baseline", cause: openErr}
	}
	defer func() {
		if closeErr := closeBaseline(); closeErr != nil && err == nil {
			err = &executionError{exitCode: ExitInternalError, message: "close diff baseline", cause: closeErr}
		}
	}()
	current, closeCurrent, openErr := openDiffInput(currentPath, cmd.InOrStdin())
	if openErr != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "open diff current", cause: openErr}
	}
	defer func() {
		if closeErr := closeCurrent(); closeErr != nil && err == nil {
			err = &executionError{exitCode: ExitInternalError, message: "close diff current", cause: closeErr}
		}
	}()

	comparison, compareErr := lifecycle.Compare(cmd.Context(), baseline, current)
	if compareErr != nil {
		return &executionError{exitCode: ExitInvalidInput, message: "compare findings", cause: compareErr}
	}
	if writeErr := lifecycle.Write(cmd.OutOrStdout(), format, comparison); writeErr != nil {
		return &executionError{exitCode: ExitInternalError, message: "write diff report", cause: writeErr}
	}
	if diffShouldFail(failOn, comparison.Summary) {
		return &executionError{exitCode: ExitPartialFailure, message: fmt.Sprintf("diff fail-on %s threshold reached", failOn)}
	}
	return nil
}

func openDiffInput(path string, stdin io.Reader) (io.Reader, func() error, error) {
	if path == "-" {
		if stdin == nil {
			return nil, func() error { return nil }, fmt.Errorf("stdin is required")
		}
		return stdin, func() error { return nil }, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, func() error { return nil }, err
	}
	return file, file.Close, nil
}

func diffShouldFail(value string, summary lifecycle.Summary) bool {
	switch value {
	case "new":
		return summary.New > 0
	case "regressed":
		return summary.Regressed > 0
	case "any-change":
		return summary.New+summary.Resolved+summary.Regressed+summary.Improved > 0
	default:
		return false
	}
}
