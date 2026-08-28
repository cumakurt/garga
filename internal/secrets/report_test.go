package secrets

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestWriteReportOmitsFullSecrets(t *testing.T) {
	t.Parallel()
	result := Result{
		SchemaVersion: SchemaVersion,
		Summary: Summary{
			TargetsScanned:   1,
			ReachableTargets: 1,
			Findings:         1,
			SeverityCounts:   map[string]int{string(SeverityCritical): 1},
			CategoryCounts:   map[string]int{"Passwords": 1},
			StartedAt:        time.Unix(0, 0).UTC(),
			FinishedAt:       time.Unix(0, 0).UTC(),
		},
		Findings: []Finding{{
			Target:        "https://es.example.internal:9200",
			Cluster:       "production",
			Index:         "application-logs-2026.08",
			DocumentID:    "doc-1",
			FieldPath:     "config.database.password",
			Category:      "credential.password",
			Detector:      "sensitive-field",
			Severity:      SeverityCritical,
			Confidence:    ConfidenceHigh,
			MaskedPreview: "f*******************Y",
			Reason:        "Sensitive field name + credential-like value",
			Timestamp:     time.Unix(0, 0).UTC(),
			Occurrences:   3,
			Secret:        "fake-password-garga-test-ONLY",
		}},
	}
	var jsonBuf bytes.Buffer
	if err := WriteReport(&jsonBuf, FormatJSON, result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(jsonBuf.String(), "fake-password-garga-test-ONLY") {
		t.Fatal("JSON report leaked secret")
	}
	var decoded map[string]any
	if err := json.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	var table bytes.Buffer
	if err := WriteReport(&table, FormatTable, result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(table.String(), "fake-password-garga-test-ONLY") {
		t.Fatal("table report leaked secret")
	}
	if !strings.Contains(table.String(), "Targets scanned: 1") {
		t.Fatalf("table missing summary: %s", table.String())
	}
	var sarif bytes.Buffer
	if err := WriteReport(&sarif, FormatSARIF, result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sarif.String(), "fake-password-garga-test-ONLY") {
		t.Fatal("SARIF report leaked secret")
	}
	var pdf bytes.Buffer
	if err := WritePDF(&pdf, result); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf.Bytes(), []byte("%PDF")) {
		t.Fatal("PDF prefix missing")
	}
	if !bytes.Contains(pdf.Bytes(), []byte("fake-password-garga-test-ONLY")) {
		t.Fatal("PDF did not include the full secret")
	}
}

func TestSyntheticDocumentsAreObviouslyFake(t *testing.T) {
	t.Parallel()
	for _, document := range append(SyntheticDocuments(), FalsePositiveDocuments()...) {
		note, _ := document.Source["note"].(string)
		if !strings.Contains(strings.ToUpper(note), "SYNTHETIC") && !strings.Contains(strings.ToUpper(note), "TEST") {
			t.Fatalf("document %s is not labeled synthetic: %v", document.ID, document.Source["note"])
		}
	}
}
