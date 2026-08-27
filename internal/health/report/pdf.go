package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	garga "github.com/cumakurt/garga"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
	"github.com/cumakurt/garga/internal/pdfdoc"
)

func writePDF(output io.Writer, report healthmodel.Report) error {
	report = sanitizeReport(report)
	generated := time.Now().UTC()
	if !report.Metadata.ScanTimestamp.IsZero() {
		generated = report.Metadata.ScanTimestamp.UTC()
	}
	doc := pdfdoc.New(
		"Elasticsearch Health Check and Assessment",
		"Confidential - Authorized Health Assessment",
		"garga GET-only health assessment",
	)
	doc.Logo(garga.LogoPNG())
	doc.Title("Elasticsearch Health Check and Assessment")
	doc.Subtitle("Evidence-based evaluation of cluster health, capacity, performance, reliability, configuration, and security. No state-changing Elasticsearch operation was performed.")
	doc.Para(fmt.Sprintf("Generated %s  |  scanner %s  |  profile %s  |  deep %t", generated.Format("2006-01-02 15:04:05 MST"), firstNonEmpty(report.Metadata.ScannerVersion, "garga"), report.Metadata.HealthProfile, report.Metadata.DeepScanEnabled))
	doc.KV("Cluster", report.Cluster.Name)
	doc.KV("Elasticsearch", report.Cluster.Version.Number)
	doc.KV("Target", report.Metadata.Target)
	doc.KV("Overall health", fmt.Sprintf("%s  |  score %d / 100", report.Summary.OverallHealth, report.Summary.HealthScore))
	doc.KV("Topology", fmt.Sprintf("%d nodes, %d indices, %d shards, %s data", report.Summary.Nodes, report.Summary.Indices, report.Summary.Shards, formatBytes(report.Summary.TotalDataBytes)))
	doc.KV("Severity counts", fmt.Sprintf("critical %d, high %d, medium %d, low %d, info %d",
		report.Summary.SeverityCounts[healthmodel.SeverityCritical],
		report.Summary.SeverityCounts[healthmodel.SeverityHigh],
		report.Summary.SeverityCounts[healthmodel.SeverityMedium],
		report.Summary.SeverityCounts[healthmodel.SeverityLow],
		report.Summary.SeverityCounts[healthmodel.SeverityInfo],
	))

	doc.Section("Top risks")
	if len(report.Summary.TopRisks) == 0 {
		doc.Para("No scored operational risks were detected by the checks that executed.")
	}
	for _, finding := range report.Summary.TopRisks {
		title := finding.Title
		if finding.Resource != "" {
			title += " (" + finding.Resource + ")"
		}
		doc.Badge(string(finding.Severity), title)
		if finding.Impact != "" {
			doc.Para(finding.Impact)
		}
	}

	doc.Section("Top resource consumers")
	writeUsageTable(doc, "Node by disk", report.Metrics.TopNodesByDisk)
	writeUsageTable(doc, "Node by JVM heap", report.Metrics.TopNodesByJVM)
	writeUsageTable(doc, "Node by shards", report.Metrics.TopNodesByShards)
	writeUsageTable(doc, "Index by storage", report.Metrics.TopIndicesByStorage)

	doc.Section("Detailed findings")
	if len(report.Findings) == 0 {
		doc.Para("No findings were produced.")
	}
	for index, finding := range report.Findings {
		resource := strings.TrimSpace(finding.ResourceType + "/" + finding.Resource)
		fields := [][]string{
			{"Category", finding.Category},
			{"Resource", resource},
			{"Confidence", string(finding.Confidence)},
			{"Threshold", finding.Threshold},
			{"Description", finding.Description},
			{"Operational impact", finding.Impact},
			{"Recommended action", finding.Recommendation},
		}
		if len(finding.Evidence) > 0 {
			fields = append(fields, []string{"Evidence", evidenceText(finding.Evidence)})
		}
		doc.FindingCard(index+1, finding.ID, string(finding.Severity), finding.Title, nil, compactHealthPDFFields(fields))
	}

	if len(report.Correlations) > 0 {
		doc.Section("Probable root causes")
		for _, item := range report.Correlations {
			doc.Badge(string(item.Severity), item.Title)
			doc.Para(item.ProbableRootCause)
			doc.KV("Confidence", string(item.Confidence))
			if len(item.FindingIDs) > 0 {
				doc.Para("Supporting checks: " + strings.Join(item.FindingIDs, ", "))
			}
		}
	}

	doc.Section("Prioritized action plan")
	writeActionGroup(doc, "P0 Immediate", report.Actions.Immediate)
	writeActionGroup(doc, "P1 Urgent", report.Actions.Urgent)
	writeActionGroup(doc, "P2 Planned", report.Actions.Planned)
	writeActionGroup(doc, "P3 Optimization", report.Actions.Optimization)

	doc.Section("Assessment coverage and scanner telemetry")
	coverage := report.Summary.CheckCoverage
	doc.KV("Checks", fmt.Sprintf("%d executed / %d available  |  passed %d  skipped %d  failed %d  findings %d", coverage.Executed, coverage.Available, coverage.Passed, coverage.Skipped, coverage.Failed, coverage.Findings))
	doc.KV("API requests", fmt.Sprintf("%d  |  retried %d  |  failed %d", report.Metadata.APIRequests, report.Metadata.RetriedRequests, report.Metadata.FailedRequests))
	doc.KV("Downloaded", formatBytes(report.Metadata.BytesDownloaded))
	doc.KV("Duration", formatDurationMillis(report.Metadata.DurationMillis))
	if len(report.Metadata.Collectors) > 0 {
		rows := make([][]string, 0, len(report.Metadata.Collectors))
		for _, collector := range report.Metadata.Collectors {
			status := collector.HTTPStatus
			statusText := "-"
			if status != 0 {
				statusText = fmt.Sprintf("%d", status)
			}
			reason := collector.Reason
			if reason == "" {
				reason = "-"
			}
			rows = append(rows, []string{collector.Name, collector.Cost, collector.Status, statusText, reason})
		}
		doc.Table([]string{"Collector", "Cost", "Status", "HTTP", "Reason"}, rows)
	}

	doc.Section("Methodology")
	doc.Para("This assessment combines cluster health, node resources, JVM, disk, shard and index architecture, workload pressure, lifecycle, backup, security, capacity, availability, and reliability evidence. The Elasticsearch cluster-health color is not used as the sole health decision.")
	doc.Para("Developer " + garga.DeveloperName + "  |  " + garga.DeveloperLinkedInURL + "  |  " + garga.DeveloperGitHubURL)
	return doc.Write(output)
}

func writeUsageTable(doc *pdfdoc.Doc, title string, values []healthmodel.ResourceUsage) {
	if len(values) == 0 {
		return
	}
	doc.Heading(title)
	rows := make([][]string, 0, len(values))
	for _, value := range values {
		rows = append(rows, []string{value.Resource, formatUsage(value)})
	}
	doc.Table([]string{"Resource", "Usage"}, rows)
}

func writeActionGroup(doc *pdfdoc.Doc, title string, items []string) {
	doc.Heading(title)
	if len(items) == 0 {
		doc.Para("None.")
		return
	}
	doc.Bullets(items)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func compactHealthPDFFields(fields [][]string) [][]string {
	out := make([][]string, 0, len(fields))
	for _, field := range fields {
		if len(field) < 2 || strings.TrimSpace(field[1]) == "" || strings.TrimSpace(field[1]) == "-" {
			continue
		}
		out = append(out, field)
	}
	return out
}

func WriteTimestampedPDF(report healthmodel.Report) (path string, err error) {
	timestamp := report.Metadata.ScanTimestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	prefix := ".garga-health-" + timestamp.UTC().Format("20060102T150405.000Z") + "-"
	return pdfdoc.WriteCWD(prefix, ".pdf", "health PDF", func(output io.Writer) error {
		return writePDF(output, report)
	})
}
