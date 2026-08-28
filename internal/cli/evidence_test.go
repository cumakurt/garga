package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/evidence"
)

func TestEvidencePackAndVerifyCommands(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "assessment.pdf")
	bundlePath := filepath.Join(directory, "evidence.zip")
	if err := os.WriteFile(artifactPath, []byte("assessment"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"evidence", "pack", "--file", artifactPath, "--output", bundlePath, "--format", "json"},
		BuildInfo{}, strings.NewReader(""), &stdout, &stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("pack exit = %d; stderr = %q", exitCode, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	exitCode = Execute(
		context.Background(),
		[]string{"evidence", "verify", bundlePath, "--format", "json"},
		BuildInfo{}, strings.NewReader(""), &stdout, &stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("verify exit = %d; stderr = %q", exitCode, stderr.String())
	}
	var result evidence.Verification
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !result.Verified || result.Artifacts != 1 || result.Signed {
		t.Fatalf("verification = %#v", result)
	}
}
