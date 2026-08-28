package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
	"github.com/cumakurt/garga/internal/health/redact"
)

const (
	ansiReset     = "\033[0m"
	ansiBold      = "\033[1m"
	ansiDim       = "\033[2m"
	ansiRed       = "\033[31m"
	ansiGreen     = "\033[32m"
	ansiYellow    = "\033[33m"
	ansiBlue      = "\033[34m"
	ansiCyan      = "\033[36m"
	ansiBrightRed = "\033[91m"
	ansiGray      = "\033[90m"

	severityColumn = 8
	bodyIndent     = "          "
	wrapWidth      = 72
	ruleLine       = "────────────────────────────────────────"
)

func writeTerminal(output io.Writer, report healthmodel.Report) error {
	_, err := io.WriteString(output, renderTerminal(report, colorEnabled(output)))
	return err
}

func renderTerminal(report healthmodel.Report, color bool) string {
	var text strings.Builder
	title := "Elasticsearch Health Check"
	if report.Metadata.AssessmentMode {
		title = "Elasticsearch Security and Health Assessment"
	}
	text.WriteString(paint(color, ansiBold+ansiCyan, title))
	text.WriteByte('\n')
	text.WriteString(paint(color, ansiGray, ruleLine))
	text.WriteByte('\n')
	writeHeadline(&text, report, color)
	writeScore(&text, report, color)
	writeOverview(&text, report, color)
	writeTopRisks(&text, report, color)
	writeConsumers(&text, report, color)
	writeFindings(&text, report, color)
	writeRootCauses(&text, report, color)
	writeActions(&text, report.Actions, color)
	writeCoverage(&text, report, color)
	writeMetadata(&text, report, color)
	return text.String()
}

func writeHeadline(text *strings.Builder, report healthmodel.Report, color bool) {
	identity := strings.TrimSpace(report.Cluster.Name)
	if version := strings.TrimSpace(report.Cluster.Version.Number); version != "" {
		if identity != "" {
			identity += "  ·  " + version
		} else {
			identity = version
		}
	}
	if identity != "" {
		text.WriteString(paint(color, ansiBold, identity))
		text.WriteByte('\n')
	}
	parts := make([]string, 0, 4)
	if target := strings.TrimSpace(report.Metadata.Target); target != "" {
		parts = append(parts, target)
	}
	if profile := strings.TrimSpace(report.Metadata.HealthProfile); profile != "" {
		parts = append(parts, "profile "+profile)
	}
	parts = append(parts, fmt.Sprintf("deep %t", report.Metadata.DeepScanEnabled))
	text.WriteString(paint(color, ansiGray, strings.Join(parts, "  ·  ")))
	text.WriteByte('\n')
}

func writeScore(text *strings.Builder, report healthmodel.Report, color bool) {
	text.WriteByte('\n')
	score := fmt.Sprintf("%d / 100", report.Summary.HealthScore)
	text.WriteString(paint(color, healthColor(report.Summary.OverallHealth), score))
	text.WriteString("  ")
	text.WriteString(paint(color, healthColor(report.Summary.OverallHealth), report.Summary.OverallHealth))
	text.WriteByte('\n')
	parts := make([]string, 0, 5)
	for _, severity := range displaySeverities() {
		count := report.Summary.SeverityCounts[severity]
		label := fmt.Sprintf("%d %s", count, strings.ToLower(string(severity)))
		if count == 0 {
			parts = append(parts, paint(color, ansiDim, label))
			continue
		}
		parts = append(parts, paint(color, severityColor(severity), label))
	}
	text.WriteString(strings.Join(parts, "    "))
	text.WriteByte('\n')
}

func writeOverview(text *strings.Builder, report healthmodel.Report, color bool) {
	writeSection(text, "Overview", color)
	writeField(text, "cluster", report.Cluster.Name)
	writeField(text, "version", report.Cluster.Version.Number)
	writeField(text, "nodes", fmt.Sprintf("%d", report.Summary.Nodes))
	writeField(text, "indices", fmt.Sprintf("%d", report.Summary.Indices))
	writeField(text, "shards", fmt.Sprintf("%d", report.Summary.Shards))
	writeField(text, "data", formatBytes(report.Summary.TotalDataBytes))
}

func writeTopRisks(text *strings.Builder, report healthmodel.Report, color bool) {
	writeSection(text, "Top risks", color)
	if len(report.Summary.TopRisks) == 0 {
		text.WriteString(paint(color, ansiDim, "No scored risks."))
		text.WriteByte('\n')
		return
	}
	for _, finding := range report.Summary.TopRisks {
		writeSeverityTitle(text, finding.Severity, finding.Title, color)
		if resource := resourceLabel(finding); resource != "" {
			writeField(text, "resource", resource)
		}
	}
}

func writeConsumers(text *strings.Builder, report healthmodel.Report, color bool) {
	rows := []struct {
		label  string
		values []healthmodel.ResourceUsage
	}{
		{"disk", report.Metrics.TopNodesByDisk},
		{"jvm", report.Metrics.TopNodesByJVM},
		{"index", report.Metrics.TopIndicesByStorage},
		{"shards", report.Metrics.TopNodesByShards},
	}
	hasValues := false
	for _, row := range rows {
		if len(row.values) > 0 {
			hasValues = true
			break
		}
	}
	if !hasValues {
		return
	}
	writeSection(text, "Resource consumers", color)
	for _, row := range rows {
		if len(row.values) == 0 {
			continue
		}
		writeField(text, row.label, formatUsageList(row.values))
	}
}

func writeFindings(text *strings.Builder, report healthmodel.Report, color bool) {
	writeSection(text, "Findings", color)
	groups := groupedFindings(report.Findings)
	if len(groups) == 0 {
		text.WriteString(paint(color, ansiGreen, "No findings."))
		text.WriteByte('\n')
		return
	}
	for index, group := range groups {
		if index > 0 {
			text.WriteByte('\n')
		}
		header := fmt.Sprintf("%s  ·  %s  (%d)", strings.ToUpper(string(group.Severity)), group.Category, len(group.Items))
		text.WriteString(paint(color, severityColor(group.Severity), header))
		text.WriteByte('\n')
		text.WriteString(paint(color, ansiGray, ruleLine))
		text.WriteByte('\n')
		for itemIndex, finding := range group.Items {
			if itemIndex > 0 {
				text.WriteByte('\n')
			}
			writeFinding(text, finding, color)
		}
	}
}

func writeFinding(text *strings.Builder, finding healthmodel.Finding, color bool) {
	writeSeverityTitle(text, finding.Severity, finding.Title, color)
	writeField(text, "check", finding.ID)
	if resource := resourceLabel(finding); resource != "" {
		writeField(text, "resource", resource)
	}
	if finding.Confidence != "" {
		writeField(text, "confidence", string(finding.Confidence))
	}
	if finding.Threshold != "" {
		writeField(text, "threshold", finding.Threshold)
	}
	if len(finding.Evidence) > 0 {
		writeField(text, "evidence", evidenceText(finding.Evidence))
	}
	if finding.Description != "" {
		writeField(text, "detail", finding.Description)
	}
	if finding.Impact != "" {
		writeField(text, "impact", finding.Impact)
	}
	if finding.RootCause != "" {
		writeField(text, "cause", finding.RootCause)
	}
	if finding.Recommendation != "" {
		writeField(text, "fix", finding.Recommendation)
	}
}

func writeRootCauses(text *strings.Builder, report healthmodel.Report, color bool) {
	if len(report.Correlations) == 0 {
		return
	}
	writeSection(text, "Probable root causes", color)
	for index, item := range report.Correlations {
		if index > 0 {
			text.WriteByte('\n')
		}
		writeSeverityTitle(text, item.Severity, item.Title, color)
		if item.Confidence != "" {
			writeField(text, "confidence", string(item.Confidence))
		}
		if item.ProbableRootCause != "" {
			writeField(text, "cause", item.ProbableRootCause)
		}
		if len(item.FindingIDs) > 0 {
			writeField(text, "checks", strings.Join(item.FindingIDs, ", "))
		}
		if len(item.Evidence) > 0 {
			writeField(text, "evidence", strings.Join(item.Evidence, "; "))
		}
	}
}

func writeActions(text *strings.Builder, actions healthmodel.Actions, color bool) {
	sections := []struct {
		priority string
		title    string
		items    []string
		tone     string
	}{
		{"P0", "immediate", actions.Immediate, severityColor(healthmodel.SeverityCritical)},
		{"P1", "urgent", actions.Urgent, severityColor(healthmodel.SeverityHigh)},
		{"P2", "planned", actions.Planned, severityColor(healthmodel.SeverityMedium)},
		{"P3", "optimization", actions.Optimization, severityColor(healthmodel.SeverityLow)},
	}
	hasItems := false
	for _, section := range sections {
		if len(section.items) > 0 {
			hasItems = true
			break
		}
	}
	if !hasItems {
		return
	}
	writeSection(text, "Actions", color)
	for _, section := range sections {
		if len(section.items) == 0 {
			continue
		}
		text.WriteString(paint(color, section.tone, section.priority+"  "+section.title))
		text.WriteByte('\n')
		for index, item := range section.items {
			prefix := fmt.Sprintf("%s%d. ", bodyIndent, index+1)
			writeWrapped(text, prefix, redact.Text(item), wrapWidth)
		}
	}
}

func writeCoverage(text *strings.Builder, report healthmodel.Report, color bool) {
	writeSection(text, "Coverage", color)
	coverage := report.Summary.CheckCoverage
	parts := []string{
		fmt.Sprintf("available %d", coverage.Available),
		fmt.Sprintf("executed %d", coverage.Executed),
		fmt.Sprintf("passed %d", coverage.Passed),
		fmt.Sprintf("findings %d", coverage.Findings),
	}
	skipped := fmt.Sprintf("skipped %d", coverage.Skipped)
	if coverage.Skipped > 0 {
		skipped = paint(color, ansiYellow, skipped)
	} else {
		skipped = paint(color, ansiDim, skipped)
	}
	failed := fmt.Sprintf("failed %d", coverage.Failed)
	if coverage.Failed > 0 {
		failed = paint(color, severityColor(healthmodel.SeverityHigh), failed)
	} else {
		failed = paint(color, ansiDim, failed)
	}
	text.WriteString(bodyIndent)
	text.WriteString(strings.Join(append(parts, skipped, failed), "    "))
	text.WriteByte('\n')
}

func writeMetadata(text *strings.Builder, report healthmodel.Report, color bool) {
	writeSection(text, "Scan metadata", color)
	writeField(text, "target", report.Metadata.Target)
	writeField(text, "profile", report.Metadata.HealthProfile)
	writeField(text, "deep", fmt.Sprintf("%t", report.Metadata.DeepScanEnabled))
	writeField(text, "duration", formatDurationMillis(report.Metadata.DurationMillis))
	writeField(text, "requests", fmt.Sprintf("%d", report.Metadata.APIRequests))
	writeField(text, "downloaded", formatBytes(report.Metadata.BytesDownloaded))
	writeField(text, "failed", fmt.Sprintf("%d", report.Metadata.FailedRequests))
	writeField(text, "retried", fmt.Sprintf("%d", report.Metadata.RetriedRequests))
	for _, collector := range report.Metadata.Collectors {
		if collector.Status == "success" || collector.Status == "" {
			continue
		}
		detail := collector.Name + ": " + collector.Status
		if collector.Reason != "" {
			detail += " (" + collector.Reason + ")"
		}
		writeField(text, "collector", detail)
	}
}

func writeSection(text *strings.Builder, title string, color bool) {
	text.WriteByte('\n')
	text.WriteString(paint(color, ansiBold+ansiCyan, title))
	text.WriteByte('\n')
	text.WriteString(paint(color, ansiGray, ruleLine))
	text.WriteByte('\n')
}

func writeSeverityTitle(text *strings.Builder, severity healthmodel.Severity, title string, color bool) {
	label := fmt.Sprintf("%-*s", severityColumn, severityLabel(severity))
	text.WriteString(paint(color, severityColor(severity), label))
	text.WriteString("  ")
	writeWrapped(text, "", title, wrapWidth)
}

func writeField(text *strings.Builder, name, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	prefix := fmt.Sprintf("%s%-12s", bodyIndent, name)
	writeWrapped(text, prefix, redact.Text(value), wrapWidth)
}

func writeWrapped(text *strings.Builder, firstPrefix, value string, width int) {
	lines := wrapText(value, width)
	if len(lines) == 0 {
		text.WriteByte('\n')
		return
	}
	if firstPrefix != "" {
		text.WriteString(firstPrefix)
		text.WriteString(lines[0])
		text.WriteByte('\n')
		for _, line := range lines[1:] {
			text.WriteString(bodyIndent)
			text.WriteString("            ")
			text.WriteString(line)
			text.WriteByte('\n')
		}
		return
	}
	text.WriteString(lines[0])
	text.WriteByte('\n')
	for _, line := range lines[1:] {
		text.WriteString(bodyIndent)
		text.WriteString(line)
		text.WriteByte('\n')
	}
}

func wrapText(value string, width int) []string {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return nil
	}
	if width < 16 {
		width = 16
	}
	words := strings.Fields(value)
	var lines []string
	current := ""
	for _, word := range words {
		if current == "" {
			current = word
			continue
		}
		if utf8.RuneCountInString(current)+1+utf8.RuneCountInString(word) <= width {
			current += " " + word
			continue
		}
		lines = append(lines, current)
		current = word
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

type findingGroup struct {
	Severity healthmodel.Severity
	Category string
	Items    []healthmodel.Finding
}

func groupedFindings(findings []healthmodel.Finding) []findingGroup {
	items := append([]healthmodel.Finding(nil), findings...)
	sort.SliceStable(items, func(left, right int) bool {
		if rank := healthmodel.SeverityRank(items[left].Severity) - healthmodel.SeverityRank(items[right].Severity); rank != 0 {
			return rank > 0
		}
		leftCategory, rightCategory := categoryLabel(items[left]), categoryLabel(items[right])
		if leftCategory != rightCategory {
			return leftCategory < rightCategory
		}
		if items[left].ID != items[right].ID {
			return items[left].ID < items[right].ID
		}
		return items[left].Resource < items[right].Resource
	})
	var groups []findingGroup
	for _, finding := range items {
		category := categoryLabel(finding)
		if len(groups) > 0 && groups[len(groups)-1].Severity == finding.Severity && groups[len(groups)-1].Category == category {
			groups[len(groups)-1].Items = append(groups[len(groups)-1].Items, finding)
			continue
		}
		groups = append(groups, findingGroup{
			Severity: finding.Severity,
			Category: category,
			Items:    []healthmodel.Finding{finding},
		})
	}
	return groups
}

func categoryLabel(finding healthmodel.Finding) string {
	if category := strings.TrimSpace(finding.Category); category != "" {
		return category
	}
	return "General"
}

func resourceLabel(finding healthmodel.Finding) string {
	resource := strings.TrimSpace(finding.Resource)
	kind := strings.TrimSpace(finding.ResourceType)
	switch {
	case resource != "" && kind != "":
		return kind + "/" + resource
	case resource != "":
		return resource
	default:
		return kind
	}
}

func formatUsageList(values []healthmodel.ResourceUsage) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, formatUsageItem(value))
	}
	return strings.Join(parts, ", ")
}

func formatUsageItem(value healthmodel.ResourceUsage) string {
	resource := strings.TrimSpace(value.Resource)
	if resource == "" {
		resource = "unknown"
	}
	switch value.Unit {
	case "bytes":
		return resource + " " + formatBytes(int64(value.Value))
	case "percent":
		return fmt.Sprintf("%s %.2f%%", resource, value.Value)
	default:
		return fmt.Sprintf("%s %.2f%s", resource, value.Value, value.Unit)
	}
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

func displaySeverities() []healthmodel.Severity {
	return []healthmodel.Severity{
		healthmodel.SeverityCritical,
		healthmodel.SeverityHigh,
		healthmodel.SeverityMedium,
		healthmodel.SeverityLow,
		healthmodel.SeverityInfo,
	}
}

func severityLabel(severity healthmodel.Severity) string {
	if severity == "" {
		return "FINDING"
	}
	return strings.ToUpper(string(severity))
}

func severityColor(severity healthmodel.Severity) string {
	switch severity {
	case healthmodel.SeverityCritical:
		return ansiBold + ansiBrightRed
	case healthmodel.SeverityHigh:
		return ansiBold + ansiRed
	case healthmodel.SeverityMedium:
		return ansiBold + ansiYellow
	case healthmodel.SeverityLow:
		return ansiBold + ansiBlue
	case healthmodel.SeverityOK:
		return ansiBold + ansiGreen
	default:
		return ansiDim
	}
}

func healthColor(label string) string {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical":
		return severityColor(healthmodel.SeverityCritical)
	case "high risk":
		return severityColor(healthmodel.SeverityHigh)
	case "degraded":
		return severityColor(healthmodel.SeverityMedium)
	case "minor issues":
		return severityColor(healthmodel.SeverityLow)
	case "healthy", "perfect":
		return severityColor(healthmodel.SeverityOK)
	default:
		return ansiDim
	}
}

func colorEnabled(output io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := output.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func paint(enabled bool, code, value string) string {
	if !enabled || value == "" {
		return value
	}
	return code + value + ansiReset
}
