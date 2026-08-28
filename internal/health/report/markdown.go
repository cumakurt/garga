package report

import (
	"fmt"
	"io"
	"strings"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
	"github.com/cumakurt/garga/internal/health/redact"
)

func writeMarkdown(output io.Writer, report healthmodel.Report) error {
	var text strings.Builder
	title := "Elasticsearch Health Check"
	if report.Metadata.AssessmentMode {
		title = "Elasticsearch Security and Health Assessment"
	}
	text.WriteString("# " + title + "\n\n")
	_, _ = fmt.Fprintf(&text, "- Cluster: %s\n- Elasticsearch: %s\n- Overall health: **%d / 100 — %s**\n- Nodes: %d\n- Indices: %d\n- Shards: %d\n- Total data: %s\n- Profile: %s\n- Deep scan: %t\n",
		markdown(report.Cluster.Name), markdown(report.Cluster.Version.Number), report.Summary.HealthScore, markdown(report.Summary.OverallHealth), report.Summary.Nodes, report.Summary.Indices, report.Summary.Shards, formatBytes(report.Summary.TotalDataBytes), markdown(report.Metadata.HealthProfile), report.Metadata.DeepScanEnabled)
	text.WriteString("\n## Top Risks\n\n")
	if len(report.Summary.TopRisks) == 0 {
		text.WriteString("No scored risks.\n")
	}
	for index, finding := range report.Summary.TopRisks {
		_, _ = fmt.Fprintf(&text, "%d. **[%s] %s** — %s\n", index+1, finding.Severity, markdown(finding.Title), markdown(finding.Resource))
	}
	text.WriteString("\n## Findings\n\n")
	for _, finding := range report.Findings {
		_, _ = fmt.Fprintf(&text, "### [%s] %s — %s\n\n", finding.Severity, finding.ID, markdown(finding.Title))
		if finding.Resource != "" {
			text.WriteString("- Resource: " + markdown(finding.Resource) + "\n")
		}
		if finding.Threshold != "" {
			text.WriteString("- Threshold: " + markdown(finding.Threshold) + "\n")
		}
		if len(finding.Evidence) > 0 {
			text.WriteString("- Evidence: `" + strings.ReplaceAll(markdown(evidenceText(finding.Evidence)), "`", "'") + "`\n")
		}
		if finding.Impact != "" {
			text.WriteString("- Impact: " + markdown(finding.Impact) + "\n")
		}
		if finding.Recommendation != "" {
			text.WriteString("- Recommendation: " + markdown(finding.Recommendation) + "\n")
		}
		text.WriteByte('\n')
	}
	if len(report.Correlations) > 0 {
		text.WriteString("## Probable Root Causes\n\n")
		for _, item := range report.Correlations {
			_, _ = fmt.Fprintf(&text, "### [%s/%s] %s\n\n%s\n\n", item.Severity, item.Confidence, markdown(item.Title), markdown(item.ProbableRootCause))
			if len(item.FindingIDs) > 0 {
				text.WriteString("- Supporting checks: " + markdown(strings.Join(item.FindingIDs, ", ")) + "\n\n")
			}
		}
	}
	writeMarkdownActions(&text, report.Actions)
	text.WriteString("## Check Coverage\n\n")
	coverage := report.Summary.CheckCoverage
	_, _ = fmt.Fprintf(&text, "Available %d; executed %d; passed %d; findings %d; skipped %d; failed %d.\n\n", coverage.Available, coverage.Executed, coverage.Passed, coverage.Findings, coverage.Skipped, coverage.Failed)
	if len(report.Metadata.Collectors) > 0 {
		text.WriteString("| Collector | Cost | Status | HTTP | Reason |\n|---|---|---|---:|---|\n")
		for _, collector := range report.Metadata.Collectors {
			reason := collector.Reason
			if reason == "" {
				reason = "—"
			}
			status := collector.HTTPStatus
			statusText := "—"
			if status != 0 {
				statusText = fmt.Sprintf("%d", status)
			}
			_, _ = fmt.Fprintf(&text, "| %s | %s | %s | %s | %s |\n", markdown(collector.Name), markdown(collector.Cost), markdown(collector.Status), statusText, markdown(reason))
		}
		text.WriteByte('\n')
	}
	text.WriteString("## Scanner Telemetry\n\n")
	_, _ = fmt.Fprintf(&text, "Requests %d; downloaded %s; failed %d; retried %d; duration %d ms.\n\n", report.Metadata.APIRequests, formatBytes(report.Metadata.BytesDownloaded), report.Metadata.FailedRequests, report.Metadata.RetriedRequests, report.Metadata.DurationMillis)
	text.WriteString("## Methodology\n\n")
	text.WriteString("This assessment combines cluster health, node resources, JVM, disk, shard and index architecture, workload pressure, lifecycle, backup, security, capacity, availability, and reliability evidence. Snapshot counters are labeled as cumulative unless a compatible baseline provides a delta. Heuristic conclusions state confidence and should be validated against workload history before configuration changes.\n")
	_, err := io.WriteString(output, text.String())
	return err
}

func writeMarkdownActions(builder *strings.Builder, actions healthmodel.Actions) {
	sections := []struct {
		title string
		items []string
	}{{"Immediate", actions.Immediate}, {"Urgent", actions.Urgent}, {"Planned", actions.Planned}, {"Optimization", actions.Optimization}}
	builder.WriteString("## Prioritized Action Plan\n\n")
	empty := true
	for _, section := range sections {
		if len(section.items) == 0 {
			continue
		}
		empty = false
		_, _ = fmt.Fprintf(builder, "### %s\n\n", section.title)
		for index, item := range section.items {
			_, _ = fmt.Fprintf(builder, "%d. %s\n", index+1, markdown(item))
		}
		builder.WriteByte('\n')
	}
	if empty {
		builder.WriteString("No prioritized actions.\n\n")
	}
}

func markdown(value string) string {
	value = redact.Text(value)
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "|", "\\|")
	return value
}
