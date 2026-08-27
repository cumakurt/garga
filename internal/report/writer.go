package report

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/cumakurt/garga/internal/model"
)

// Format identifies a supported report encoding.
type Format string

const (
	FormatConsole Format = "console"
	FormatJSON    Format = "json"
	FormatJSONL   Format = "jsonl"
	FormatCSV     Format = "csv"
	FormatHTML    Format = "html"
)

// Writer emits findings one at a time. Close completes the document.
type Writer interface {
	Write(ctx context.Context, finding model.Finding) error
	Close() error
}

// New creates a reporter for format. JSONL and JSON stream without retaining
// findings. Console buffers until Close so output can be grouped by target and
// severity. Color is used only on a terminal when NO_COLOR is unset.
func New(format Format, output io.Writer) (Writer, error) {
	if output == nil {
		return nil, fmt.Errorf("create report writer: output is required")
	}
	switch format {
	case FormatConsole:
		return &consoleWriter{output: output, color: colorEnabled(output)}, nil
	case FormatJSON:
		return &jsonWriter{output: output}, nil
	case FormatJSONL:
		return &jsonlWriter{output: output}, nil
	case FormatCSV:
		return newCSVWriter(output), nil
	case FormatHTML:
		return &htmlWriter{output: output}, nil
	default:
		return nil, fmt.Errorf("create report writer: format is not supported")
	}
}

// ParseFormat validates a configured or CLI report format name.
func ParseFormat(value string) (Format, error) {
	format := Format(strings.ToLower(strings.TrimSpace(value)))
	switch format {
	case FormatConsole, FormatJSON, FormatJSONL, FormatCSV, FormatHTML:
		return format, nil
	default:
		return "", fmt.Errorf("parse report format: format is not supported")
	}
}

func prepared(finding model.Finding) model.Finding {
	if finding.SchemaVersion == "" {
		finding.SchemaVersion = model.FindingSchemaVersion
	}
	return markExploitable(finding)
}

func evidenceCodes(finding model.Finding) []string {
	if len(finding.Evidence) == 0 {
		return nil
	}
	codes := make([]string, 0, len(finding.Evidence))
	for _, item := range finding.Evidence {
		if item.Code != "" {
			codes = append(codes, item.Code)
		}
	}
	return codes
}
