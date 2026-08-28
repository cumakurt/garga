package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/logging"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/report"
	"github.com/spf13/cobra"
)

func newReportCommand() *cobra.Command {
	var (
		format     string
		inputPath  string
		configPath string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render JSONL findings into a report format",
		Long: strings.TrimSpace(`
Read JSONL findings from stdin or --input and write a console, JSON, JSONL,
CSV, standalone HTML, SARIF, or CycloneDX VEX report.
The command does not contact the network.

Each input line must be one finding JSON object. Invalid records fail the
command without echoing the payload. Console output is human-oriented and is
not a machine schema contract. Machine formats use finding schema 0.1.
`),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd, reportOptions{
				format:     format,
				inputPath:  inputPath,
				configPath: configPath,
			})
		},
	}
	cmd.Flags().StringVar(&format, "format", "", "output format: console, json, jsonl, csv, html, sarif, or vex (default console)")
	cmd.Flags().StringVar(&inputPath, "input", "", "JSONL findings file (default: stdin)")
	cmd.Flags().StringVar(&configPath, "config", "", "optional configuration file")
	return cmd
}

type reportOptions struct {
	format     string
	inputPath  string
	configPath string
}

func runReport(cmd *cobra.Command, options reportOptions) (err error) {
	cfg, err := config.Load(config.Options{ConfigPath: options.configPath})
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

	input, closer, err := openReportInput(options.inputPath, cmd.InOrStdin())
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := closer(); closeErr != nil && err == nil {
			err = &executionError{exitCode: ExitInternalError, message: "close report input", cause: closeErr}
		}
	}()

	writer, err := report.New(format, cmd.OutOrStdout())
	if err != nil {
		return &executionError{exitCode: ExitInternalError, message: "create report writer", cause: err}
	}
	if format != report.FormatConsole {
		writer = report.WithNotice(writer, cmd.ErrOrStderr())
	}
	defer func() {
		if closeErr := writer.Close(); closeErr != nil && err == nil {
			err = &executionError{exitCode: ExitInternalError, message: "write report", cause: closeErr}
		}
	}()

	decodeErr := report.DecodeJSONL(cmd.Context(), input, func(finding model.Finding) error {
		return writer.Write(cmd.Context(), finding)
	})
	if decodeErr != nil {
		return classifyReportError(decodeErr)
	}
	newLogger(cfg.Logging.Level, cmd.ErrOrStderr()).Debug(
		"report written",
		logging.Bounded("format", string(format), "console", "json", "jsonl", "csv", "html", "sarif", "vex"),
	)
	return nil
}

func openReportInput(path string, stdin io.Reader) (io.Reader, func() error, error) {
	if path == "" || path == "-" {
		if stdin == nil {
			return nil, func() error { return nil }, &executionError{
				exitCode: ExitInvalidInput,
				message:  "report input is required",
			}
		}
		return stdin, func() error { return nil }, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, func() error { return nil }, &executionError{
			exitCode: ExitInvalidInput,
			message:  "open report input",
			cause:    err,
		}
	}
	return file, file.Close, nil
}

func classifyReportError(err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	message := err.Error()
	if strings.HasPrefix(message, "decode finding:") {
		return &executionError{exitCode: ExitInvalidInput, message: message, cause: err}
	}
	return &executionError{exitCode: ExitInternalError, message: "write report", cause: err}
}
