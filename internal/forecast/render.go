package forecast

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type Format string

const (
	FormatConsole Format = "console"
	FormatJSON    Format = "json"
)

func ParseFormat(value string) (Format, error) {
	format := Format(strings.ToLower(strings.TrimSpace(value)))
	if format != FormatConsole && format != FormatJSON {
		return "", fmt.Errorf("forecast format must be console or json")
	}
	return format, nil
}

func Write(output io.Writer, format Format, report Report) error {
	if output == nil {
		return fmt.Errorf("write forecast: output is required")
	}
	if format == FormatJSON {
		return json.NewEncoder(output).Encode(report)
	}
	if format != FormatConsole {
		return fmt.Errorf("write forecast: format is not supported")
	}
	if _, err := fmt.Fprintf(
		output,
		"Capacity forecast: %d samples over %.1f hours (%s confidence, R2 %.3f)\n",
		report.Samples,
		report.WindowHours,
		report.Growth.Confidence,
		report.Growth.R2,
	); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(
		output,
		"Current disk: %.1f%% used (%s used, %s free); store growth: %s/day (%s)\n",
		report.Capacity.UsagePercent,
		formatBytes(report.Capacity.DiskUsedBytes),
		formatBytes(report.Capacity.DiskFreeBytes),
		formatSignedBytes(report.Growth.BytesPerDay),
		report.Growth.Direction,
	); err != nil {
		return err
	}
	for _, projection := range report.Projections {
		detail := projection.State
		if projection.EstimatedAt != nil && projection.Days != nil {
			detail = fmt.Sprintf("%s in %.1f days (%s)", projection.State, *projection.Days, projection.EstimatedAt.UTC().Format("2006-01-02"))
		} else if projection.Days != nil {
			detail = fmt.Sprintf("%s after %.1f days", projection.State, *projection.Days)
		}
		if _, err := fmt.Fprintf(output, "%d%% threshold: %s\n", projection.ThresholdPercent, detail); err != nil {
			return err
		}
	}
	return nil
}

func formatSignedBytes(value float64) string {
	prefix := "+"
	if value < 0 {
		prefix = "-"
		value = -value
	}
	return prefix + formatFloatBytes(value)
}

func formatBytes(value int64) string {
	return formatFloatBytes(float64(value))
}

func formatFloatBytes(value float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	size := value
	unit := 0
	for size >= 1024 && unit < len(units)-1 {
		size /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f %s", size, units[unit])
}
