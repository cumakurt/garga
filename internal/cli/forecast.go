package cli

import (
	"fmt"
	"path/filepath"

	"github.com/cumakurt/garga/internal/forecast"
	"github.com/cumakurt/garga/internal/health"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
	"github.com/spf13/cobra"
)

func newForecastCommand() *cobra.Command {
	var formatValue string
	cmd := &cobra.Command{
		Use:   "forecast SNAPSHOT SNAPSHOT [SNAPSHOT...]",
		Short: "Forecast Elasticsearch disk thresholds from health snapshots",
		Long: `Analyze 2-64 secret-free health baseline files without contacting the network.
The forecast uses observed cluster-store growth, current disk usage, capacity
consistency, and regression fit to project the 85%, 90%, and 95% thresholds.`,
		Args:          cobra.RangeArgs(2, forecast.MaxSnapshots),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := forecast.ParseFormat(formatValue)
			if err != nil {
				return &executionError{exitCode: ExitInvalidInput, message: err.Error(), cause: err}
			}
			snapshots := make([]*healthmodel.Baseline, 0, len(args))
			remainingBytes := int64(forecast.MaxTotalSnapshotBytes)
			for _, path := range args {
				snapshot, consumedBytes, loadErr := health.LoadBaselineBounded(path, remainingBytes)
				if loadErr != nil {
					return &executionError{
						exitCode: ExitInvalidInput,
						message:  fmt.Sprintf("invalid forecast snapshot %q", filepath.Base(path)),
						cause:    loadErr,
					}
				}
				remainingBytes -= consumedBytes
				snapshots = append(snapshots, snapshot)
			}
			report, err := forecast.Analyze(snapshots)
			if err != nil {
				return &executionError{exitCode: ExitInvalidInput, message: err.Error(), cause: err}
			}
			if err := forecast.Write(cmd.OutOrStdout(), format, report); err != nil {
				return &executionError{exitCode: ExitInternalError, message: "write forecast report", cause: err}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&formatValue, "format", string(forecast.FormatConsole), "output format: console or json")
	return cmd
}
