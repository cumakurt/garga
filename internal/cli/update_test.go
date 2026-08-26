package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateHelpDocumentsSignedInstall(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"update", "--help"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	help := stdout.String()
	for _, needle := range []string{"--source", "--dir", "--rollback", "Ed25519", "atomically"} {
		if !strings.Contains(help, needle) {
			t.Errorf("help missing %q: %s", needle, help)
		}
	}
}

func TestUpdateRequiresDirAndSource(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"update", "--source", t.TempDir()},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("missing dir exit = %d, want %d; stderr = %q", exitCode, ExitInvalidInput, stderr.String())
	}

	stderr.Reset()
	exitCode = Execute(
		context.Background(),
		[]string{"update", "--dir", t.TempDir()},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("missing source exit = %d, want %d; stderr = %q", exitCode, ExitInvalidInput, stderr.String())
	}
}

func TestUpdateRejectsUnsignedBundleWithExitFour(t *testing.T) {
	t.Parallel()

	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "manifest.json"), []byte(`{"schema_version":"0.1"}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "manifest.sig"), []byte("00"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "signatures.zip"), []byte("not-a-zip"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"update", "--source", source, "--dir", t.TempDir()},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitUpdateFailure {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, ExitUpdateFailure, stderr.String())
	}
	if strings.Contains(stderr.String(), "not-a-zip") {
		t.Fatalf("stderr echoed payload: %q", stderr.String())
	}
}

func TestUpdateRollbackWithoutPreviousFails(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"update", "--rollback", "--dir", t.TempDir()},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitUpdateFailure {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, ExitUpdateFailure, stderr.String())
	}
}

func TestUpdateRejectsRollbackWithSource(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"update", "--rollback", "--source", t.TempDir(), "--dir", t.TempDir()},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, ExitInvalidInput, stderr.String())
	}
}
