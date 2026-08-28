package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/model"
)

const reportXSSTitle = "</td><script>alert(1)</script>"

const reportJSONLInput = `{"schema_version":"1.0","id":"garga.exposure.anonymous_access|http://192.168.1.10:9200/|","check_id":"garga.exposure.anonymous_access","title":"</td><script>alert(1)</script>","target":{"scheme":"http","host":"192.168.1.10","port":9200},"product":"elasticsearch","severity":"high","confidence":"medium"}` + "\n"

func TestReportHelpDocumentsJSONLInput(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"report", "--help"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	help := stdout.String()
	for _, needle := range []string{"--format", "--input", "JSONL", "html", "does not contact the network"} {
		if !strings.Contains(help, needle) {
			t.Errorf("help missing %q: %s", needle, help)
		}
	}
}

func TestReportJSONAndJSONLParse(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"report", "--format", "json"},
		BuildInfo{},
		strings.NewReader(reportJSONLInput),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("json exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	var document struct {
		SchemaVersion string          `json:"schema_version"`
		Findings      []model.Finding `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; stdout = %s", err, stdout.String())
	}
	if document.SchemaVersion != model.FindingSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", document.SchemaVersion, model.FindingSchemaVersion)
	}
	if len(document.Findings) != 1 || document.Findings[0].Title != reportXSSTitle {
		t.Fatalf("json findings = %#v", document.Findings)
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = Execute(
		context.Background(),
		[]string{"report", "--format", "jsonl"},
		BuildInfo{},
		strings.NewReader(reportJSONLInput),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("jsonl exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	var finding model.Finding
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &finding); err != nil {
		t.Fatalf("jsonl unmarshal error = %v; stdout = %s", err, stdout.String())
	}
	if finding.CheckID != "garga.exposure.anonymous_access" {
		t.Fatalf("jsonl check_id = %q", finding.CheckID)
	}
}

func TestReportHTMLEscapesXSSFromInputFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	inputPath := filepath.Join(dir, "findings.jsonl")
	if err := os.WriteFile(inputPath, []byte(reportJSONLInput), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"report", "--format", "html", "--input", inputPath},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	output := stdout.String()
	if strings.Contains(output, "</td><script>") || strings.Contains(output, "<script>") {
		t.Fatalf("HTML did not escape XSS payload: %s", output)
	}
	if !strings.Contains(output, html.EscapeString(reportXSSTitle)) {
		t.Fatalf("HTML missing escaped title: %s", output)
	}
}

func TestReportRejectsInvalidJSONWithoutEchoingPayload(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"report", "--format", "json"},
		BuildInfo{},
		strings.NewReader(`{"check_id":`+canary+`}`+"\n"),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, ExitInvalidInput, stderr.String())
	}
	if strings.Contains(stdout.String(), canary) || strings.Contains(stderr.String(), canary) {
		t.Fatalf("invalid record echoed payload: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestReportRejectsUnsupportedFormat(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"report", "--format", "xml"},
		BuildInfo{},
		strings.NewReader(reportJSONLInput),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, ExitInvalidInput, stderr.String())
	}
	if !strings.Contains(stderr.String(), "report format is not supported") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
