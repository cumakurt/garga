package secrets

import (
	"fmt"
	"io"
	"strings"
	"time"

	garga "github.com/cumakurt/garga"
	"github.com/cumakurt/garga/internal/pdfdoc"
)

func WritePDF(output io.Writer, result Result) error {
	generated := result.Summary.FinishedAt.UTC()
	if generated.IsZero() {
		generated = time.Now().UTC()
	}
	doc := pdfdoc.New(
		"Elasticsearch Sensitive Data Discovery",
		"Confidential - Authorized Secret Scan - Full secret values included",
		"garga secrets read-only discovery",
	)
	doc.Logo(garga.LogoPNG())
	doc.Title("Elasticsearch Sensitive Data Discovery")
	doc.Subtitle("Authorized read-only scan of index mappings and sampled documents. Console and machine-readable reports stay masked; this PDF includes recovered secret values except private keys and password hashes.")
	doc.Para(fmt.Sprintf("Generated %s  |  schema %s  |  scan mode %s", generated.Format("2006-01-02 15:04:05 MST"), result.SchemaVersion, strings.ToUpper(string(result.Summary.ScanMode))))
	doc.KV("Targets scanned", fmt.Sprintf("%d (reachable %d)", result.Summary.TargetsScanned, result.Summary.ReachableTargets))
	doc.KV("Indices inspected", fmt.Sprintf("%d", result.Summary.IndicesInspected))
	doc.KV("Documents sampled", fmt.Sprintf("%d", result.Summary.DocumentsSampled))
	doc.KV("Fields examined", fmt.Sprintf("%d", result.Summary.FieldsExamined))
	doc.KV("Bytes examined", fmt.Sprintf("%d", result.Summary.BytesExamined))
	doc.KV("Scan duration", fmt.Sprintf("%dms", result.Summary.ScanDurationMS))
	doc.KV("Findings", fmt.Sprintf("%d (field %d, correlated %d)", result.Summary.Findings, result.Summary.FieldFindings, result.Summary.CorrelatedFindings))
	doc.KV("Severity counts", fmt.Sprintf("critical %d, high %d, medium %d, low %d, info %d",
		result.Summary.SeverityCounts[string(SeverityCritical)],
		result.Summary.SeverityCounts[string(SeverityHigh)],
		result.Summary.SeverityCounts[string(SeverityMedium)],
		result.Summary.SeverityCounts[string(SeverityLow)],
		result.Summary.SeverityCounts[string(SeverityInfo)],
	))
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
		if item.Error != "" {
			doc.KV("Error", item.Error)
		}
	}

	doc.Section("Findings")
	if len(result.Findings) == 0 {
		doc.Para("No sensitive findings were reported at the configured confidence threshold.")
	}
	for _, finding := range result.Findings {
		doc.Badge(string(finding.Severity), finding.Category+" / "+finding.FieldPath)
		doc.KV("Target", finding.Target)
		doc.KV("Cluster", finding.Cluster)
		doc.KV("Index", finding.Index)
		doc.KV("Document", finding.DocumentID)
		doc.KV("Detector", finding.Detector)
		doc.KV("Confidence", string(finding.Confidence))
		if finding.ObjectPath != "" {
			doc.KV("Object path", finding.ObjectPath)
		}
		if len(finding.RelatedFields) > 0 {
			doc.KV("Related fields", strings.Join(finding.RelatedFields, ", "))
		}
		if finding.CredentialType != "" {
			doc.KV("Credential type", finding.CredentialType)
		}
		doc.KV("Occurrences", fmt.Sprintf("%d", finding.Occurrences))
		doc.KV("Reason", finding.Reason)
		doc.KV("Masked preview", finding.MaskedPreview)
		secret := strings.TrimSpace(finding.Secret)
		if secret == "" {
			doc.KV("Secret value", finding.MaskedPreview)
		} else {
			doc.KV("Secret value", secret)
		}
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

func WriteTimestampedPDF(result Result) (string, error) {
	timestamp := result.Summary.FinishedAt
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	prefix := ".garga-secrets-" + timestamp.UTC().Format("20060102T150405.000Z") + "-"
	return pdfdoc.WriteCWD(prefix, ".pdf", "secrets PDF", func(output io.Writer) error {
		return WritePDF(output, result)
	})
}
