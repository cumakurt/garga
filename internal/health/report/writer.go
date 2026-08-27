package report

import (
	"fmt"
	"io"
	"strings"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
	"github.com/cumakurt/garga/internal/health/redact"
)

type Format string

const (
	FormatTerminal Format = "terminal"
	FormatJSON     Format = "json"
	FormatHTML     Format = "html"
	FormatMarkdown Format = "markdown"
)

func ParseFormat(value string) (Format, error) {
	format := Format(strings.ToLower(strings.TrimSpace(value)))
	if format == "console" {
		format = FormatTerminal
	}
	switch format {
	case FormatTerminal, FormatJSON, FormatHTML, FormatMarkdown:
		return format, nil
	default:
		return "", fmt.Errorf("health report format must be terminal, json, html, or markdown")
	}
}

func Write(output io.Writer, format Format, report healthmodel.Report) error {
	if output == nil {
		return fmt.Errorf("write health report: output is required")
	}
	report = sanitizeReport(report)
	switch format {
	case FormatTerminal:
		return writeTerminal(output, report)
	case FormatJSON:
		return writeJSON(output, report)
	case FormatHTML:
		return writeHTML(output, report)
	case FormatMarkdown:
		return writeMarkdown(output, report)
	default:
		return fmt.Errorf("write health report: format is unsupported")
	}
}

func sanitizeReport(report healthmodel.Report) healthmodel.Report {
	report.Cluster.Name = redact.Text(report.Cluster.Name)
	report.Findings = append([]healthmodel.Finding(nil), report.Findings...)
	for index := range report.Findings {
		report.Findings[index] = sanitizeFinding(report.Findings[index])
	}
	report.Summary.TopRisks = append([]healthmodel.Finding(nil), report.Summary.TopRisks...)
	for index := range report.Summary.TopRisks {
		report.Summary.TopRisks[index] = sanitizeFinding(report.Summary.TopRisks[index])
	}
	report.Correlations = append([]healthmodel.Correlation(nil), report.Correlations...)
	for index := range report.Correlations {
		report.Correlations[index].Title = redact.Text(report.Correlations[index].Title)
		report.Correlations[index].ProbableRootCause = redact.Text(report.Correlations[index].ProbableRootCause)
		report.Correlations[index].FindingIDs = append([]string(nil), report.Correlations[index].FindingIDs...)
		report.Correlations[index].Evidence = append([]string(nil), report.Correlations[index].Evidence...)
	}
	report.Metadata.Target = redact.Text(report.Metadata.Target)
	return report
}
