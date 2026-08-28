package secrets

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkAnalyzeField(b *testing.B) {
	for index := 0; index < b.N; index++ {
		_ = AnalyzeField("services.accounts[12].clientSecret")
	}
}

func BenchmarkDetectCredentialValue(b *testing.B) {
	semantics := AnalyzeField("authorization")
	value := "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJnYXJnYS10ZXN0In0.GARGA_TEST_SIGNATURE"
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_ = detectValue(value, semantics, DefaultMaxFieldBytes)
	}
}

func BenchmarkBuildSummaryTenThousandFindings(b *testing.B) {
	report := largeBenchmarkReport(MaxReportFindings)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_ = buildSummary(report.Summary.ScanMode, report.Targets, report.Findings, report.Summary.StartedAt, report.Summary.FinishedAt)
	}
}

func BenchmarkValidateTenThousandFindingReport(b *testing.B) {
	report := largeBenchmarkReport(MaxReportFindings)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := ValidateResult(report); err != nil {
			b.Fatal(err)
		}
	}
}

func largeBenchmarkReport(count int) ScanReport {
	started := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	targets := []TargetReport{{
		Target: "https://benchmark.example:9200", Reachable: true, IndicesInspected: 100,
		DocumentsSampled: count, DocumentsExamined: count, FieldsExamined: count,
	}}
	findings := make([]Finding, count)
	for index := range findings {
		findings[index] = Finding{
			ID: fmt.Sprintf("SEC-%06d", index+1), Title: "Sensitive credential material detected",
			Target: targets[0].Target, Index: fmt.Sprintf("logs-%03d", index%100), DocumentID: fmt.Sprintf("doc-%d", index),
			FieldPath: "password", Category: "credential.password", Detector: "sensitive-field",
			Severity: SeverityCritical, Confidence: ConfidenceHigh, MaskedPreview: "s********t",
			Reason: "Sensitive field name + credential-like value", Remediation: "Rotate the credential.",
			Timestamp: started, Occurrences: 1,
		}
	}
	finished := started.Add(time.Second)
	return ScanReport{
		SchemaVersion: SchemaVersion,
		Targets:       targets,
		Findings:      findings,
		Summary:       buildSummary(ScanModeDeep, targets, findings, started, finished),
	}
}
