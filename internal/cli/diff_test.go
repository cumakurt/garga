package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/lifecycle"
)

func TestDiffCommandWritesLifecycleJSONAndEnforcesFailOn(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	baseline := filepath.Join(directory, "baseline.jsonl")
	current := filepath.Join(directory, "current.jsonl")
	baseRecord := `{"schema_version":"0.1","id":"finding-a","check_id":"garga.test","title":"test","target":{"scheme":"https","host":"es.example.com","port":9200},"product":"Elasticsearch","severity":"medium","confidence":"high","applicability":"potential","priority_score":5}` + "\n"
	currentRecord := `{"schema_version":"0.1","id":"finding-a","check_id":"garga.test","title":"test","target":{"scheme":"https","host":"es.example.com","port":9200},"product":"Elasticsearch","severity":"high","confidence":"high","applicability":"applicable","priority_score":9}` + "\n"
	if err := os.WriteFile(baseline, []byte(baseRecord), 0o600); err != nil {
		t.Fatalf("WriteFile(baseline) error = %v", err)
	}
	if err := os.WriteFile(current, []byte(currentRecord), 0o600); err != nil {
		t.Fatalf("WriteFile(current) error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"diff", "--baseline", baseline, "--current", current, "--format", "json", "--fail-on", "regressed"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitPartialFailure {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, ExitPartialFailure, stderr.String())
	}
	var document lifecycle.Report
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; output = %s", err, stdout.String())
	}
	if document.Summary.Regressed != 1 || len(document.Changes) != 1 {
		t.Fatalf("diff report = %#v", document)
	}
	if !strings.Contains(stderr.String(), "fail-on regressed") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestDiffCommandValidatesInputs(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"diff", "--baseline", "-", "--current", "-"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput || !strings.Contains(stderr.String(), "only one diff input") {
		t.Fatalf("exit code/stderr = %d/%q", exitCode, stderr.String())
	}
}
