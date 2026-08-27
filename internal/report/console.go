package report

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cumakurt/garga/internal/model"
)

const (
	ansiReset      = "\033[0m"
	ansiBold       = "\033[1m"
	ansiDim        = "\033[2m"
	ansiRed        = "\033[31m"
	ansiYellow     = "\033[33m"
	ansiBlue       = "\033[34m"
	ansiCyan       = "\033[36m"
	ansiBrightRed  = "\033[91m"
	ansiGray       = "\033[90m"
	ansiInverse    = "\033[7m"
	severityColumn = 8
	bodyIndent     = "          "
	wrapWidth      = 72
	ruleLine       = "────────────────────────────────────────"
)

type consoleWriter struct {
	output io.Writer
	color  bool
	items  []model.Finding
	closed bool
}

func (writer *consoleWriter) Write(ctx context.Context, finding model.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if writer.closed {
		return errWriterClosed
	}
	writer.items = append(writer.items, prepared(finding))
	return nil
}

func (writer *consoleWriter) Close() error {
	if writer.closed {
		return nil
	}
	writer.closed = true
	text := renderConsole(writer.items, writer.color)
	_, err := io.WriteString(writer.output, text)
	return err
}

func renderConsole(findings []model.Finding, color bool) string {
	if len(findings) == 0 {
		return "No findings.\n"
	}

	groups := groupByTarget(findings)
	var b strings.Builder
	for index, group := range groups {
		if index > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(paint(color, ansiBold+ansiCyan, group.target))
		b.WriteByte('\n')
		b.WriteString(paint(color, ansiGray, ruleLine))
		b.WriteByte('\n')
		for _, finding := range group.items {
			b.WriteByte('\n')
			writeFinding(&b, finding, color)
		}
	}
	b.WriteByte('\n')
	b.WriteString(paint(color, ansiGray, ruleLine))
	b.WriteByte('\n')
	b.WriteString(renderSummary(findings, color))
	b.WriteByte('\n')
	return b.String()
}

type targetGroup struct {
	target string
	items  []model.Finding
}

func groupByTarget(findings []model.Finding) []targetGroup {
	index := map[string]int{}
	var groups []targetGroup
	for _, finding := range findings {
		key := targetDisplay(finding.Target)
		if position, ok := index[key]; ok {
			groups[position].items = append(groups[position].items, finding)
			continue
		}
		index[key] = len(groups)
		groups = append(groups, targetGroup{target: key, items: []model.Finding{finding}})
	}
	sort.SliceStable(groups, func(left, right int) bool {
		return groups[left].target < groups[right].target
	})
	for i := range groups {
		items := groups[i].items
		sort.SliceStable(items, func(left, right int) bool {
			leftExploitable, rightExploitable := exploitable(items[left]), exploitable(items[right])
			if leftExploitable != rightExploitable {
				return leftExploitable
			}
			if rank := severityRank(items[left].Severity) - severityRank(items[right].Severity); rank != 0 {
				return rank > 0
			}
			if items[left].CheckID != items[right].CheckID {
				return items[left].CheckID < items[right].CheckID
			}
			return items[left].Resource < items[right].Resource
		})
		groups[i].items = items
	}
	return groups
}

func writeFinding(b *strings.Builder, finding model.Finding, color bool) {
	label := fmt.Sprintf("%-*s", severityColumn, severityLabel(finding.Severity))
	b.WriteString(paint(color, severityColor(finding.Severity), label))
	b.WriteString("  ")
	if exploitable(finding) {
		b.WriteString(paint(color, ansiBold+ansiBrightRed+ansiInverse, " EXPLOITABLE "))
		b.WriteString("  ")
	}
	writeWrapped(b, "", finding.Title, wrapWidth)
	if exploitable(finding) {
		writeField(b, "note", exploitableNote(finding))
	}

	writeField(b, "check", finding.CheckID)
	if finding.Resource != "" {
		writeField(b, "resource", finding.Resource)
	}
	if finding.Confidence != "" {
		writeField(b, "confidence", string(finding.Confidence))
	}
	if finding.Version != "" {
		writeField(b, "version", finding.Version)
	}
	if len(finding.CVE) > 0 {
		writeField(b, "cve", strings.Join(finding.CVE, ", "))
	}
	if finding.CVSS != nil {
		writeField(b, "cvss", strconv.FormatFloat(*finding.CVSS, 'f', 1, 64))
	}
	if codes := evidenceCodes(finding); len(codes) > 0 {
		writeField(b, "evidence", strings.Join(codes, ", "))
	}
	if finding.Description != "" {
		writeField(b, "detail", finding.Description)
	}
	if finding.Remediation != "" {
		writeField(b, "fix", finding.Remediation)
	}
}

func writeField(b *strings.Builder, name, value string) {
	prefix := fmt.Sprintf("%s%-12s", bodyIndent, name)
	writeWrapped(b, prefix, value, wrapWidth)
}

func writeWrapped(b *strings.Builder, firstPrefix, text string, width int) {
	lines := wrapText(text, width)
	if len(lines) == 0 {
		b.WriteByte('\n')
		return
	}
	indent := bodyIndent
	if firstPrefix != "" {
		b.WriteString(firstPrefix)
		b.WriteString(lines[0])
		b.WriteByte('\n')
		for _, line := range lines[1:] {
			b.WriteString(indent)
			b.WriteString("            ")
			b.WriteString(line)
			b.WriteByte('\n')
		}
		return
	}
	b.WriteString(lines[0])
	b.WriteByte('\n')
	for _, line := range lines[1:] {
		b.WriteString(indent)
		b.WriteString(line)
		b.WriteByte('\n')
	}
}

func wrapText(text string, width int) []string {
	text = strings.Join(strings.Fields(text), " ")
	if text == "" {
		return nil
	}
	if width < 16 {
		width = 16
	}
	words := strings.Fields(text)
	var lines []string
	var current string
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

func renderSummary(findings []model.Finding, color bool) string {
	counts := map[model.Severity]int{}
	exploitableCount := 0
	for _, finding := range findings {
		counts[finding.Severity]++
		if exploitable(finding) {
			exploitableCount++
		}
	}
	parts := []string{fmt.Sprintf("%d findings", len(findings))}
	if exploitableCount > 0 {
		parts = append(parts, paint(color, ansiBold+ansiBrightRed, fmt.Sprintf("%d exploitable", exploitableCount)))
	}
	for _, severity := range []model.Severity{
		model.SeverityCritical,
		model.SeverityHigh,
		model.SeverityMedium,
		model.SeverityLow,
		model.SeverityInfo,
	} {
		n := counts[severity]
		if n == 0 {
			continue
		}
		label := fmt.Sprintf("%d %s", n, severity)
		parts = append(parts, paint(color, severityColor(severity), label))
	}
	return strings.Join(parts, "    ")
}

func severityLabel(severity model.Severity) string {
	if severity == "" {
		return "FINDING"
	}
	return strings.ToUpper(string(severity))
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func severityColor(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return ansiBold + ansiBrightRed
	case model.SeverityHigh:
		return ansiBold + ansiRed
	case model.SeverityMedium:
		return ansiBold + ansiYellow
	case model.SeverityLow:
		return ansiBold + ansiBlue
	default:
		return ansiDim
	}
}

func targetDisplay(endpoint model.Endpoint) string {
	rawURL, err := endpoint.URL()
	if err != nil {
		return endpoint.Host
	}
	return rawURL
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

func paint(enabled bool, code, text string) string {
	if !enabled || text == "" {
		return text
	}
	return code + text + ansiReset
}

// ColorEnabled reports whether ANSI color should be written to output.
func ColorEnabled(output io.Writer) bool {
	return colorEnabled(output)
}

// Paint wraps text in ANSI codes when enabled.
func Paint(enabled bool, code, text string) string {
	return paint(enabled, code, text)
}
