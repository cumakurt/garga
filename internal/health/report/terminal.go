package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
	"github.com/cumakurt/garga/internal/health/redact"
)

func writeTerminal(output io.Writer, report healthmodel.Report) error {
	var text strings.Builder
	text.WriteString("ELASTICSEARCH HEALTH CHECK\n")
	text.WriteString("==========================\n\n")
	writeKV(&text, "Cluster", report.Cluster.Name)
	writeKV(&text, "Version", report.Cluster.Version.Number)
	writeKV(&text, "Nodes", fmt.Sprintf("%d", report.Summary.Nodes))
	writeKV(&text, "Indices", fmt.Sprintf("%d", report.Summary.Indices))
	writeKV(&text, "Shards", fmt.Sprintf("%d", report.Summary.Shards))
	writeKV(&text, "Total data", formatBytes(report.Summary.TotalDataBytes))
	text.WriteString("\nOVERALL HEALTH\n--------------\n")
	_, _ = fmt.Fprintf(&text, "%d / 100  %s\n", report.Summary.HealthScore, report.Summary.OverallHealth)
	_, _ = fmt.Fprintf(&text, "Critical %d  High %d  Medium %d  Low %d  Info %d\n",
		report.Summary.SeverityCounts[healthmodel.SeverityCritical], report.Summary.SeverityCounts[healthmodel.SeverityHigh],
		report.Summary.SeverityCounts[healthmodel.SeverityMedium], report.Summary.SeverityCounts[healthmodel.SeverityLow], report.Summary.SeverityCounts[healthmodel.SeverityInfo])

	text.WriteString("\nTOP RISKS\n---------\n")
	if len(report.Summary.TopRisks) == 0 {
		text.WriteString("No scored risks.\n")
	}
	for index, finding := range report.Summary.TopRisks {
		_, _ = fmt.Fprintf(&text, "%d. [%s] %s", index+1, finding.Severity, finding.Title)
		if finding.Resource != "" {
			text.WriteString(" (" + finding.Resource + ")")
		}
		text.WriteByte('\n')
	}

	text.WriteString("\nTOP RESOURCE CONSUMERS\n----------------------\n")
	writeUsage(&text, "Disk", report.Metrics.TopNodesByDisk)
	writeUsage(&text, "JVM", report.Metrics.TopNodesByJVM)
	writeUsage(&text, "Index storage", report.Metrics.TopIndicesByStorage)
	writeUsage(&text, "Node shards", report.Metrics.TopNodesByShards)

	text.WriteString("\nFINDINGS\n--------\n")
	if len(report.Findings) == 0 {
		text.WriteString("No findings.\n")
	}
	for _, finding := range report.Findings {
		_, _ = fmt.Fprintf(&text, "\n[%s] %s\n%s\n", finding.Severity, finding.ID, finding.Title)
		if finding.Resource != "" {
			writeKV(&text, "Resource", finding.Resource)
		}
		if len(finding.Evidence) > 0 {
			writeKV(&text, "Evidence", evidenceText(finding.Evidence))
		}
		if finding.Threshold != "" {
			writeKV(&text, "Threshold", finding.Threshold)
		}
		if finding.Impact != "" {
			writeKV(&text, "Impact", finding.Impact)
		}
		if finding.Recommendation != "" {
			writeKV(&text, "Recommendation", finding.Recommendation)
		}
		if finding.Confidence != "" {
			writeKV(&text, "Confidence", string(finding.Confidence))
		}
	}

	if len(report.Correlations) > 0 {
		text.WriteString("\nPROBABLE ROOT CAUSES\n--------------------\n")
		for _, item := range report.Correlations {
			_, _ = fmt.Fprintf(&text, "[%s/%s] %s\n%s\n", item.Severity, item.Confidence, item.Title, item.ProbableRootCause)
		}
	}

	writeActions(&text, report.Actions)
	coverage := report.Summary.CheckCoverage
	text.WriteString("\nCHECK COVERAGE\n--------------\n")
	_, _ = fmt.Fprintf(&text, "Available %d  Executed %d  Passed %d  Findings %d  Skipped %d  Failed %d\n", coverage.Available, coverage.Executed, coverage.Passed, coverage.Findings, coverage.Skipped, coverage.Failed)
	text.WriteString("\nSCAN METADATA\n-------------\n")
	writeKV(&text, "Target", report.Metadata.Target)
	writeKV(&text, "Profile", report.Metadata.HealthProfile)
	writeKV(&text, "Deep scan", fmt.Sprintf("%t", report.Metadata.DeepScanEnabled))
	writeKV(&text, "Duration", fmt.Sprintf("%d ms", report.Metadata.DurationMillis))
	writeKV(&text, "API requests", fmt.Sprintf("%d", report.Metadata.APIRequests))
	writeKV(&text, "Downloaded", formatBytes(report.Metadata.BytesDownloaded))
	writeKV(&text, "Failed requests", fmt.Sprintf("%d", report.Metadata.FailedRequests))
	writeKV(&text, "Retried requests", fmt.Sprintf("%d", report.Metadata.RetriedRequests))
	for _, collector := range report.Metadata.Collectors {
		if collector.Status != "success" {
			writeKV(&text, "Collector", fmt.Sprintf("%s: %s (%s)", collector.Name, collector.Status, collector.Reason))
		}
	}
	_, err := io.WriteString(output, text.String())
	return err
}

func writeKV(builder *strings.Builder, key, value string) {
	_, _ = fmt.Fprintf(builder, "%-16s %s\n", key, redact.Text(value))
}

func writeUsage(builder *strings.Builder, label string, values []healthmodel.ResourceUsage) {
	if len(values) == 0 {
		return
	}
	builder.WriteString(label + ": ")
	parts := make([]string, 0, len(values))
	for _, value := range values {
		display := fmt.Sprintf("%s=%.2f%s", value.Resource, value.Value, value.Unit)
		switch value.Unit {
		case "bytes":
			display = value.Resource + "=" + formatBytes(int64(value.Value))
		case "percent":
			display = fmt.Sprintf("%s=%.2f%%", value.Resource, value.Value)
		}
		parts = append(parts, display)
	}
	builder.WriteString(strings.Join(parts, ", ") + "\n")
}

func evidenceText(evidence map[string]any) string {
	keys := make([]string, 0, len(evidence))
	for key := range evidence {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", key, evidence[key]))
	}
	return strings.Join(parts, ", ")
}

func formatBytes(value int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB"}
	size := float64(value)
	unit := 0
	for size >= 1024 && unit < len(units)-1 {
		size /= 1024
		unit++
	}
	return fmt.Sprintf("%.2f %s", size, units[unit])
}

func writeActions(builder *strings.Builder, actions healthmodel.Actions) {
	sections := []struct {
		title string
		items []string
	}{{"P0 IMMEDIATE ACTIONS", actions.Immediate}, {"P1 URGENT ACTIONS", actions.Urgent}, {"P2 PLANNED ACTIONS", actions.Planned}, {"P3 OPTIMIZATION", actions.Optimization}}
	for _, section := range sections {
		if len(section.items) == 0 {
			continue
		}
		builder.WriteString("\n" + section.title + "\n" + strings.Repeat("-", len(section.title)) + "\n")
		for index, item := range section.items {
			_, _ = fmt.Fprintf(builder, "%d. %s\n", index+1, item)
		}
	}
}
