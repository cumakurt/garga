package secrets

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	garga "github.com/cumakurt/garga"
	"github.com/cumakurt/garga/internal/pdfdoc"
)

func WritePDF(output io.Writer, result ScanReport) error {
	if err := ValidateResult(result); err != nil {
		return fmt.Errorf("validate secrets report: %w", err)
	}
	generated := result.Summary.FinishedAt.UTC()
	if generated.IsZero() {
		generated = time.Now().UTC()
	}
	doc := pdfdoc.New(
		"Elasticsearch Sensitive Data Discovery",
		"Confidential - Authorized Secret Scan - Masked Values Only",
		"garga secrets read-only discovery",
	)
	doc.SetDocumentTime(generated)
	doc.Logo(garga.LogoPNG())
	doc.Title("Elasticsearch Sensitive Data Discovery")
	doc.Subtitle("Authorized read-only scan of index mappings and sampled documents. All report outputs use the same canonical, masked finding model.")
	doc.Para(fmt.Sprintf("Generated %s  |  schema %s  |  scan mode %s", generated.Format("2006-01-02 15:04:05 MST"), result.SchemaVersion, strings.ToUpper(string(result.Summary.ScanMode))))
	doc.KV("Targets scanned", fmt.Sprintf("%d (reachable %d)", result.Summary.TargetsScanned, result.Summary.ReachableTargets))
	doc.KV("Indices inspected", fmt.Sprintf("%d", result.Summary.IndicesInspected))
	doc.KV("Documents sampled", fmt.Sprintf("%d", result.Summary.DocumentsSampled))
	doc.KV("Documents examined", fmt.Sprintf("%d", result.Summary.DocumentsExamined))
	doc.KV("Fields examined", fmt.Sprintf("%d", result.Summary.FieldsExamined))
	doc.KV("Bytes examined", fmt.Sprintf("%d", result.Summary.BytesExamined))
	doc.KV("Scan duration", fmt.Sprintf("%dms", result.Summary.ScanDurationMS))
	doc.KV("Findings", fmt.Sprintf("%d (field %d, correlated %d)", result.Summary.Findings, result.Summary.FieldFindings, result.Summary.CorrelatedFindings))
	doc.KV("Occurrences", fmt.Sprintf("%d", result.Summary.Occurrences))
	if result.Summary.PartialFailures > 0 {
		doc.KV("Partial failures", fmt.Sprintf("%d", result.Summary.PartialFailures))
	}
	if result.Summary.FindingsTruncated {
		doc.KV("Finding limit reached", "true")
	}
	doc.KV("Severity counts", fmt.Sprintf("CRITICAL %d, HIGH %d, MEDIUM %d, LOW %d, INFO %d",
		result.Summary.SeverityCounts[string(SeverityCritical)],
		result.Summary.SeverityCounts[string(SeverityHigh)],
		result.Summary.SeverityCounts[string(SeverityMedium)],
		result.Summary.SeverityCounts[string(SeverityLow)],
		result.Summary.SeverityCounts[string(SeverityInfo)],
	))
	if rows := sortedCountRows(result.Summary.CategoryCounts); len(rows) > 0 {
		doc.Heading("Category distribution")
		doc.Table([]string{"Category", "Findings"}, rows)
	}
	if rows := sortedCountRows(result.Summary.CorrelationCounts); len(rows) > 0 {
		doc.Heading("Credential correlations")
		doc.Table([]string{"Correlation", "Findings"}, rows)
	}
	doc.PageBreak()

	doc.Section("Targets")
	if len(result.Targets) == 0 {
		doc.Para("No targets were scanned.")
	}
	for _, item := range result.Targets {
		status := "unreachable"
		if item.Reachable {
			status = "reachable"
		}
		title := item.Target + " (" + status + ")"
		doc.Heading(title)
		doc.KV("Cluster", item.Cluster)
		doc.KV("Version", item.Version)
		if item.Authenticated {
			doc.KV("Authenticated identity", item.AuthIdentity)
		}
		doc.KV("Indices inspected", fmt.Sprintf("%d", item.IndicesInspected))
		doc.KV("Documents sampled", fmt.Sprintf("%d", item.DocumentsSampled))
		doc.KV("Documents examined", fmt.Sprintf("%d", item.DocumentsExamined))
		doc.KV("Fields examined", fmt.Sprintf("%d", item.FieldsExamined))
		doc.KV("Bytes examined", fmt.Sprintf("%d", item.BytesExamined))
		if item.Error != "" {
			doc.KV("Error", item.Error)
		}
	}

	doc.Section("Findings")
	if len(result.Findings) == 0 {
		doc.Para("No sensitive findings were reported at the configured confidence threshold.")
	}
	for index, finding := range result.Findings {
		fields := [][]string{
			{"Category", prettyCategory(finding.Category)},
			{"Target", finding.Target},
			{"Cluster", finding.Cluster},
			{"Index", finding.Index},
			{"Document", finding.DocumentID},
			{"Field path", finding.FieldPath},
			{"Detector", finding.Detector},
			{"Confidence", string(finding.Confidence)},
		}
		if finding.ObjectPath != "" {
			fields = append(fields, []string{"Object path", finding.ObjectPath})
		}
		if len(finding.RelatedFields) > 0 {
			fields = append(fields, []string{"Related fields", strings.Join(finding.RelatedFields, ", ")})
		}
		if finding.CredentialType != "" {
			fields = append(fields, []string{"Credential type", finding.CredentialType})
		}
		if maskedValues := maskedValuesText(finding.MaskedValues); maskedValues != "" {
			fields = append(fields, []string{"Masked values", maskedValues})
		}
		fields = append(fields,
			[]string{"Occurrences", fmt.Sprintf("%d", finding.Occurrences)},
			[]string{"Reason", finding.Reason},
			[]string{"Masked preview", finding.MaskedPreview},
			[]string{"Remediation", finding.Remediation},
		)
		doc.FindingCard(index+1, finding.ID, string(finding.Severity), finding.Title, nil, fields)
	}

	doc.Section("Limitations")
	doc.Bullets([]string{
		"This scan samples documents. Absence of a finding is not proof that an index contains no secrets.",
		"Private keys and password hashes are reported by type only and are never dumped.",
		"Use only against Elasticsearch clusters you own or are authorized to assess.",
		"https://www.linkedin.com/in/cuma-kurt-34414917/",
		"https://github.com/cumakurt",
	})
	return doc.Write(output)
}

func sortedCountRows(counts map[string]int) [][]string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := make([][]string, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, []string{key, fmt.Sprintf("%d", counts[key])})
	}
	return rows
}

func maskedValuesText(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values[key])
	}
	return strings.Join(parts, ", ")
}

func WriteTimestampedPDF(result ScanReport) (string, error) {
	timestamp := result.Summary.FinishedAt
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	prefix := ".garga-secrets-" + timestamp.UTC().Format("20060102T150405.000Z") + "-"
	return pdfdoc.WriteCWD(prefix, ".pdf", "secrets PDF", func(output io.Writer) error {
		return WritePDF(output, result)
	})
}
