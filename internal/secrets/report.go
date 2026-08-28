package secrets

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// Format is a secrets reporter encoding.
type Format string

const (
	FormatJSON  Format = "json"
	FormatJSONL Format = "jsonl"
	FormatTable Format = "table"
	FormatSARIF Format = "sarif"
)

type publicFinding struct {
	Target         string            `json:"target"`
	Cluster        string            `json:"cluster"`
	Index          string            `json:"index"`
	DocumentID     string            `json:"document_id"`
	FieldPath      string            `json:"field_path"`
	ObjectPath     string            `json:"object_path,omitempty"`
	RelatedFields  []string          `json:"related_fields,omitempty"`
	CredentialType string            `json:"credential_type,omitempty"`
	Category       string            `json:"category"`
	Detector       string            `json:"detector"`
	Severity       Severity          `json:"severity"`
	Confidence     Confidence        `json:"confidence"`
	MaskedPreview  string            `json:"masked_preview"`
	MaskedValues   map[string]string `json:"masked_values,omitempty"`
	Reason         string            `json:"reason"`
	Timestamp      time.Time         `json:"timestamp"`
	Occurrences    int               `json:"occurrences"`
}

type publicResult struct {
	SchemaVersion string          `json:"schema_version"`
	Summary       Summary         `json:"summary"`
	Targets       []TargetReport  `json:"targets"`
	Findings      []publicFinding `json:"findings"`
}

func publicFindings(findings []Finding) []publicFinding {
	out := make([]publicFinding, 0, len(findings))
	for _, finding := range findings {
		out = append(out, publicFinding{
			Target:         finding.Target,
			Cluster:        finding.Cluster,
			Index:          finding.Index,
			DocumentID:     finding.DocumentID,
			FieldPath:      finding.FieldPath,
			ObjectPath:     finding.ObjectPath,
			RelatedFields:  finding.RelatedFields,
			CredentialType: finding.CredentialType,
			Category:       finding.Category,
			Detector:       finding.Detector,
			Severity:       finding.Severity,
			Confidence:     finding.Confidence,
			MaskedPreview:  finding.MaskedPreview,
			MaskedValues:   finding.MaskedValues,
			Reason:         finding.Reason,
			Timestamp:      finding.Timestamp,
			Occurrences:    finding.Occurrences,
		})
	}
	return out
}

func WriteReport(output io.Writer, format Format, result Result) error {
	switch format {
	case FormatJSON:
		encoder := json.NewEncoder(output)
		encoder.SetIndent("", "  ")
		return encoder.Encode(publicResult{
			SchemaVersion: result.SchemaVersion,
			Summary:       result.Summary,
			Targets:       result.Targets,
			Findings:      publicFindings(result.Findings),
		})
	case FormatJSONL:
		encoder := json.NewEncoder(output)
		for _, finding := range publicFindings(result.Findings) {
			if err := encoder.Encode(finding); err != nil {
				return err
			}
		}
		return nil
	case FormatTable:
		return writeTable(output, result)
	case FormatSARIF:
		return writeSARIF(output, result)
	default:
		return fmt.Errorf("secrets format is not supported")
	}
}

func writeTable(output io.Writer, result Result) error {
	if _, err := fmt.Fprintln(output, FormatSummary(result.Summary)); err != nil {
		return err
	}
	if len(result.Findings) == 0 {
		_, err := fmt.Fprintln(output, "No sensitive findings at the configured confidence threshold.")
		return err
	}
	writer := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "SEVERITY\tCONFIDENCE\tCATEGORY\tINDEX\tFIELD\tOCCURRENCES\tPREVIEW"); err != nil {
		return err
	}
	for _, finding := range result.Findings {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			finding.Severity, finding.Confidence, finding.Category, finding.Index, finding.FieldPath, finding.Occurrences, finding.MaskedPreview); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func FormatSummary(summary Summary) string {
	var builder strings.Builder
	mode := summary.ScanMode
	if mode == "" {
		mode = ScanModeNormal
	}
	fmt.Fprintf(&builder, "Scan mode: %s\n", strings.ToUpper(string(mode)))
	fmt.Fprintf(&builder, "Targets scanned: %d\n", summary.TargetsScanned)
	fmt.Fprintf(&builder, "Reachable targets: %d\n", summary.ReachableTargets)
	fmt.Fprintf(&builder, "Indices inspected: %d\n", summary.IndicesInspected)
	fmt.Fprintf(&builder, "Documents sampled: %d\n", summary.DocumentsSampled)
	fmt.Fprintf(&builder, "Documents examined: %d\n", summary.DocumentsExamined)
	fmt.Fprintf(&builder, "Fields examined: %d\n", summary.FieldsExamined)
	fmt.Fprintf(&builder, "Bytes examined: %d\n", summary.BytesExamined)
	fmt.Fprintf(&builder, "Scan duration: %dms\n\n", summary.ScanDurationMS)
	builder.WriteString("Sensitive findings:\n\n")
	for _, severity := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		fmt.Fprintf(&builder, "%s: %d\n", strings.ToUpper(string(severity)), summary.SeverityCounts[string(severity)])
	}
	fmt.Fprintf(&builder, "\nField findings: %d\n", summary.FieldFindings)
	fmt.Fprintf(&builder, "Correlated findings: %d\n", summary.CorrelatedFindings)
	builder.WriteString("\nCategories:\n\n")
	keys := make([]string, 0, len(summary.CategoryCounts))
	for key := range summary.CategoryCounts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&builder, "%s: %d\n", key, summary.CategoryCounts[key])
	}
	if len(summary.CorrelationCounts) > 0 {
		builder.WriteString("\nCredential Correlations:\n\n")
		corrKeys := make([]string, 0, len(summary.CorrelationCounts))
		for key := range summary.CorrelationCounts {
			corrKeys = append(corrKeys, key)
		}
		sort.Strings(corrKeys)
		for _, key := range corrKeys {
			fmt.Fprintf(&builder, "%s: %d\n", key, summary.CorrelationCounts[key])
		}
	}
	if len(summary.TopIndices) > 0 {
		builder.WriteString("\nTop indices:\n\n")
		for _, item := range summary.TopIndices {
			fmt.Fprintf(&builder, "%s: %d\n", item.Index, item.Count)
		}
	}
	return builder.String()
}

func writeSARIF(output io.Writer, result Result) error {
	rules := map[string]struct{}{}
	var results []map[string]any
	for _, finding := range result.Findings {
		rules[finding.Detector] = struct{}{}
		results = append(results, map[string]any{
			"ruleId": finding.Detector,
			"level":  sarifLevel(finding.Severity),
			"message": map[string]any{
				"text": finding.Reason + " (" + finding.MaskedPreview + ")",
			},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": finding.Target},
					"logicalLocations": []map[string]any{{
						"fullyQualifiedName": finding.Index + "/" + finding.FieldPath,
					}},
				},
			}},
			"properties": map[string]any{
				"category":        finding.Category,
				"confidence":      finding.Confidence,
				"occurrences":     finding.Occurrences,
				"document_id":     finding.DocumentID,
				"cluster":         finding.Cluster,
				"object_path":     finding.ObjectPath,
				"related_fields":  finding.RelatedFields,
				"credential_type": finding.CredentialType,
			},
		})
	}
	var ruleList []map[string]any
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ruleList = append(ruleList, map[string]any{"id": id, "name": id})
	}
	document := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "garga secrets",
					"informationUri": "https://github.com/cumakurt/garga",
					"rules":          ruleList,
				},
			},
			"results": results,
		}},
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func sarifLevel(severity Severity) string {
	switch severity {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
