package lifecycle

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
	FormatJSONL   Format = "jsonl"
)

func ParseFormat(value string) (Format, error) {
	format := Format(strings.ToLower(strings.TrimSpace(value)))
	switch format {
	case FormatConsole, FormatJSON, FormatJSONL:
		return format, nil
	default:
		return "", fmt.Errorf("parse lifecycle format: format is not supported")
	}
}

func Write(output io.Writer, format Format, report Report) error {
	if output == nil {
		return fmt.Errorf("write lifecycle report: output is required")
	}
	switch format {
	case FormatConsole:
		return writeConsole(output, report)
	case FormatJSON:
		return json.NewEncoder(output).Encode(report)
	case FormatJSONL:
		encoder := json.NewEncoder(output)
		for _, change := range report.Changes {
			if err := encoder.Encode(change); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("write lifecycle report: format is not supported")
	}
}

func writeConsole(output io.Writer, report Report) error {
	if _, err := fmt.Fprintf(
		output,
		"Finding lifecycle: %d new, %d regressed, %d improved, %d resolved, %d unchanged\n",
		report.Summary.New,
		report.Summary.Regressed,
		report.Summary.Improved,
		report.Summary.Resolved,
		report.Summary.Unchanged,
	); err != nil {
		return err
	}
	for _, change := range report.Changes {
		title := ""
		if change.Current != nil {
			title = change.Current.Title
		} else if change.Previous != nil {
			title = change.Previous.Title
		}
		if _, err := fmt.Fprintf(output, "%-10s %s  %s\n", strings.ToUpper(string(change.Status)), change.ID, title); err != nil {
			return err
		}
		for _, reason := range change.Reasons {
			if _, err := fmt.Fprintf(output, "           %s\n", reason); err != nil {
				return err
			}
		}
	}
	return nil
}
