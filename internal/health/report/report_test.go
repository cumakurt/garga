package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func TestWriteFormatsAndRedactsSensitiveEvidence(t *testing.T) {
	t.Parallel()
	report := fixtureReport()
	formats := []Format{FormatTerminal, FormatJSON, FormatHTML, FormatMarkdown}
	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			t.Parallel()
			var output bytes.Buffer
			if err := Write(&output, format, report); err != nil {
				t.Fatalf("Write() error = %v", err)
			}
			text := output.String()
			if !strings.Contains(text, "Elasticsearch Health Check") && !strings.Contains(text, "ELASTICSEARCH HEALTH CHECK") && !strings.Contains(text, `"schema_version":"1.0"`) {
				t.Fatalf("output is not a health report: %s", text)
			}
			if strings.Contains(text, "credential-canary") || strings.Contains(text, "Basic abc") {
				t.Fatalf("output leaked sensitive evidence: %s", text)
			}
			if format == FormatHTML && strings.Contains(strings.ToLower(text), "<script") {
				t.Fatalf("HTML contains a script: %s", text)
			}
			if format == FormatMarkdown && (!strings.Contains(text, "Prioritized Action Plan") || !strings.Contains(text, "Probable Root Causes") || !strings.Contains(text, "Methodology") || !strings.Contains(text, "| Collector |")) {
				t.Fatalf("markdown report is missing coverage sections: %s", text)
			}
		})
	}
}

func TestJSONReportSchema(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := Write(&output, FormatJSON, fixtureReport()); err != nil {
		t.Fatal(err)
	}
	var document struct {
		SchemaVersion string           `json:"schema_version"`
		Cluster       map[string]any   `json:"cluster"`
		Summary       map[string]any   `json:"summary"`
		Metrics       map[string]any   `json:"metrics"`
		Findings      []map[string]any `json:"findings"`
		Metadata      map[string]any   `json:"metadata"`
	}
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if document.SchemaVersion != "1.0" || document.Cluster == nil || document.Summary == nil || document.Metrics == nil || document.Findings == nil || document.Metadata == nil {
		t.Fatalf("schema document = %#v", document)
	}
}

func TestWriteTimestampedHTMLCreatesPrivateStandaloneArtifact(t *testing.T) {
	t.Chdir(t.TempDir())
	path, err := WriteTimestampedHTML(fixtureReport())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != mustWorkingDirectory(t) || !strings.HasPrefix(filepath.Base(path), "garga-health-20260827T120000.000Z-") {
		t.Fatalf("artifact path = %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact permissions = %o", info.Mode().Perm())
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"data:image/png;base64,", "garga logo", "Executive Summary", "Detailed Findings", "Prioritized Action Plan", "Assessment Coverage", "https://www.linkedin.com/in/cuma-kurt-34414917/", "https://github.com/cumakurt", "Cuma Kurt"} {
		if !bytes.Contains(payload, []byte(expected)) {
			t.Fatalf("artifact does not contain %q", expected)
		}
	}
}

func mustWorkingDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func fixtureReport() healthmodel.Report {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	return healthmodel.Report{
		SchemaVersion: healthmodel.ReportSchemaVersion,
		Cluster:       healthmodel.ClusterInfo{Name: "production", Version: healthmodel.Version{Number: "8.19.19"}, Nodes: 3, Indices: 10, Shards: 20, StoreBytes: 1024},
		Summary: healthmodel.Summary{
			OverallHealth: "Degraded", HealthScore: 70, SeverityCounts: map[healthmodel.Severity]int{healthmodel.SeverityHigh: 1}, Nodes: 3, Indices: 10, Shards: 20, TotalDataBytes: 1024,
			TopRisks: []healthmodel.Finding{{ID: "ES-DISK-001", Severity: healthmodel.SeverityHigh, Title: "Disk pressure", Resource: "data-1"}}, CheckCoverage: healthmodel.CheckCoverage{Available: 2, Executed: 2, Passed: 1, Findings: 1},
		},
		Metrics: healthmodel.Metrics{TopNodesByDisk: []healthmodel.ResourceUsage{{Resource: "data-1", Value: 91, Unit: "percent"}}},
		Findings: []healthmodel.Finding{{
			ID: "ES-DISK-001", Category: "Disk", Severity: healthmodel.SeverityHigh, Title: "Disk pressure", ResourceType: "node", Resource: "data-1",
			Evidence: map[string]any{"authorization": "Basic abc", "password": "credential-canary"}, Threshold: "85%", Impact: "Allocation can stop.", Recommendation: "Free storage.", Confidence: healthmodel.ConfidenceHigh,
		}},
		Correlations: []healthmodel.Correlation{{Title: "Disk pressure is preventing normal allocation or writes", ProbableRootCause: "Insufficient free disk.", Severity: healthmodel.SeverityHigh, Confidence: healthmodel.ConfidenceHigh, FindingIDs: []string{"ES-DISK-001"}}},
		Actions:      healthmodel.Actions{Urgent: []string{"Free storage on data-1."}},
		Metadata:     healthmodel.Metadata{ScannerVersion: "test", ScanTimestamp: now, Target: "https://es.example:9200/", ElasticsearchVersion: "8.19.19", HealthProfile: "production", APIRequests: 10, BytesDownloaded: 1024, Collectors: []healthmodel.CollectorResult{{Name: "root", Cost: "LOW", Status: "success", HTTPStatus: 200}}},
	}
}
