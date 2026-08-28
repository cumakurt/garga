package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const plaintextCanary = "GARGA_TEST_SECRET_7F4D91A2"

func TestCanonicalReportRenderersStayMaskedAndPreserveSummary(t *testing.T) {
	t.Parallel()
	result := reportFixture()
	if err := ValidateResult(result); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%#v", result), plaintextCanary) {
		t.Fatal("canonical result retained the plaintext canary")
	}

	var jsonBuffer bytes.Buffer
	if err := WriteReport(&jsonBuffer, FormatJSON, result); err != nil {
		t.Fatal(err)
	}
	var decoded Result
	if err := json.Unmarshal(jsonBuffer.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Summary, result.Summary) {
		t.Fatalf("JSON summary differs from canonical summary:\n got: %#v\nwant: %#v", decoded.Summary, result.Summary)
	}

	var table bytes.Buffer
	if err := WriteReport(&table, FormatTable, result); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"Targets scanned: 1",
		"Reachable targets: 1",
		"Indices inspected: 2",
		"Documents examined: 4",
		"Sensitive findings: 2",
		"CRITICAL: 1",
		"HIGH: 1",
		"Correlated findings: 1",
		"Occurrences: 5",
		"Passwords: 1",
		"Username + Password: 1",
	} {
		if !strings.Contains(table.String(), expected) {
			t.Errorf("table summary missing %q", expected)
		}
	}

	var sarif bytes.Buffer
	if err := WriteReport(&sarif, FormatSARIF, result); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sarif.Bytes(), []byte(`"severity": "CRITICAL"`)) {
		t.Fatal("SARIF omitted canonical severity")
	}
	var pdf bytes.Buffer
	if err := WritePDF(&pdf, result); err != nil {
		t.Fatal(err)
	}
	var secondPDF bytes.Buffer
	if err := WritePDF(&secondPDF, result); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pdf.Bytes(), secondPDF.Bytes()) {
		offset := firstByteDifference(pdf.Bytes(), secondPDF.Bytes())
		t.Fatalf("rendering the same canonical report produced a different PDF at byte %d", offset)
	}
	if !bytes.HasPrefix(pdf.Bytes(), []byte("%PDF")) {
		t.Fatal("PDF prefix missing")
	}
	for _, expected := range []string{
		"Targets scanned", "reachable 1", "Indices inspected", "Documents examined",
		"Findings", "field 1, correlated 1", "CRITICAL 1, HIGH 1, MEDIUM 0, LOW 0, INFO 0", "Occurrences", "Passwords",
		"Credential correlations", "Username + Password", "SEC-000001", "SEC-000002",
	} {
		if !bytes.Contains(pdf.Bytes(), []byte(expected)) {
			t.Errorf("PDF summary missing %q", expected)
		}
	}
	for name, payload := range map[string][]byte{
		"JSON":  jsonBuffer.Bytes(),
		"table": table.Bytes(),
		"SARIF": sarif.Bytes(),
		"PDF":   pdf.Bytes(),
	} {
		if bytes.Contains(payload, []byte(plaintextCanary)) {
			t.Errorf("%s report leaked the plaintext canary", name)
		}
	}
	for _, format := range []Format{FormatJSON, FormatJSONL, FormatTable, FormatSARIF} {
		var first, second bytes.Buffer
		if err := WriteReport(&first, format, result); err != nil {
			t.Fatal(err)
		}
		if err := WriteReport(&second, format, result); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Bytes(), second.Bytes()) {
			t.Errorf("format %s is not deterministic", format)
		}
	}
}

func firstByteDifference(left, right []byte) int {
	limit := min(len(left), len(right))
	for index := 0; index < limit; index++ {
		if left[index] != right[index] {
			return index
		}
	}
	return limit
}

func TestValidateResultRejectsBrokenCanonicalInvariants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*Result)
	}{
		{"missing finding ID", func(result *Result) { result.Findings[0].ID = "" }},
		{"duplicate finding ID", func(result *Result) { result.Findings[1].ID = result.Findings[0].ID }},
		{"invalid severity", func(result *Result) { result.Findings[0].Severity = Severity("urgent") }},
		{"invalid confidence", func(result *Result) { result.Findings[0].Confidence = Confidence("certain") }},
		{"zero occurrences", func(result *Result) { result.Findings[0].Occurrences = 0 }},
		{"summary mismatch", func(result *Result) { result.Summary.Findings++ }},
		{"negative target counter", func(result *Result) { result.Targets[0].DocumentsExamined = -1 }},
		{"invalid timestamps", func(result *Result) { result.Summary.FinishedAt = time.Time{} }},
		{"empty schema version", func(result *Result) { result.SchemaVersion = "" }},
		{"invalid scan mode", func(result *Result) { result.Summary.ScanMode = ScanMode("full") }},
		{"incomplete finding", func(result *Result) { result.Findings[0].Title = "" }},
		{"empty location", func(result *Result) { result.Findings[0].FieldPath = "" }},
		{"empty preview", func(result *Result) { result.Findings[0].MaskedPreview = "" }},
		{"retained fingerprint", func(result *Result) { result.Findings[0].dedupFingerprint = "retained" }},
		{"empty target address", func(result *Result) { result.Targets[0].Target = "" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := reportFixture()
			test.mutate(&result)
			if err := ValidateResult(result); err == nil {
				t.Fatal("ValidateResult accepted an invalid canonical report")
			}
		})
	}
}

func TestWriteReportFileIsAtomicPrivateAndRejectsSymlink(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "secrets.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteReportFile(path, FormatJSON, reportFixture()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("report permissions = %o", info.Mode().Perm())
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(payload, []byte("old")) || !json.Valid(payload) {
		t.Fatal("report file was not atomically replaced with JSON")
	}

	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "link.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := WriteReportFile(symlink, FormatJSON, reportFixture()); err == nil {
		t.Fatal("WriteReportFile replaced a symbolic link")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "preserve" {
		t.Fatal("symlink target changed")
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

func reportFixture() Result {
	started := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	finished := started.Add(1500 * time.Millisecond)
	targets := []TargetReport{{
		Target:            "https://es.example.internal:9200",
		Reachable:         true,
		Cluster:           "production",
		Version:           "9.1.0",
		Authenticated:     true,
		AuthIdentity:      "scanner",
		IndicesInspected:  2,
		DocumentsSampled:  4,
		DocumentsExamined: 4,
		FieldsExamined:    12,
		BytesExamined:     1024,
	}}
	findings := []Finding{
		{
			ID: "SEC-000001", Title: "Sensitive credential material detected",
			Target: targets[0].Target, Cluster: targets[0].Cluster, Index: "application-logs-2026.08", DocumentID: "doc-1",
			FieldPath: "config.database.password", Category: "credential.password", Detector: "sensitive-field",
			Severity: SeverityCritical, Confidence: ConfidenceHigh, MaskedPreview: "GARGA_...91A2",
			Reason: "Sensitive field name + credential-like value", Remediation: "Rotate the credential.", Timestamp: started, Occurrences: 3,
		},
		{
			ID: "SEC-000002", Title: "Correlated credential material detected",
			Target: targets[0].Target, Cluster: targets[0].Cluster, Index: "application-logs-2026.08", DocumentID: "doc-2",
			FieldPath: "accounts[0]", ObjectPath: "accounts[0]", RelatedFields: []string{"accounts[0].username", "accounts[0].password"}, CredentialType: "username_password",
			Category: "credential.pair", Detector: "credential-pair", Severity: SeverityHigh, Confidence: ConfidenceHigh,
			MaskedPreview: "username=a*** password=GARGA_...91A2", MaskedValues: map[string]string{"username": "a***", "password": "GARGA_...91A2"},
			Reason: "Username and password fields detected within the same object", Remediation: "Rotate the credential pair.", Timestamp: started, Occurrences: 2,
		},
	}
	return Result{
		SchemaVersion: SchemaVersion,
		Targets:       targets,
		Findings:      findings,
		Summary:       buildSummary(ScanModeNormal, targets, findings, started, finished),
	}
}
