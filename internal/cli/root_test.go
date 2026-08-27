package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type failingWriter struct {
	err error
}

func (writer failingWriter) Write(_ []byte) (int, error) {
	return 0, writer.err
}

func TestExecuteHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Execute(
		context.Background(),
		[]string{"--help"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)

	if exitCode != ExitSuccess {
		t.Fatalf("Execute() exit code = %d, want %d; stderr = %q", exitCode, ExitSuccess, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Errorf("help output %q does not contain Usage section", stdout.String())
	}
	if !strings.Contains(stdout.String(), "scan") {
		t.Errorf("help output %q does not list scan command", stdout.String())
	}
	if !strings.Contains(stdout.String(), "fingerprint") {
		t.Errorf("help output %q does not list fingerprint command", stdout.String())
	}
	if !strings.Contains(stdout.String(), "vuln") {
		t.Errorf("help output %q does not list vuln command", stdout.String())
	}
	if !strings.Contains(stdout.String(), "version") {
		t.Errorf("help output %q does not list version command", stdout.String())
	}
	if !strings.Contains(stdout.String(), "auth-check") {
		t.Errorf("help output %q does not list auth-check command", stdout.String())
	}
	if !strings.Contains(stdout.String(), "auth-audit") {
		t.Errorf("help output %q does not list auth-audit command", stdout.String())
	}
	if !strings.Contains(stdout.String(), "report") {
		t.Errorf("help output %q does not list report command", stdout.String())
	}
	if !strings.Contains(stdout.String(), "update") {
		t.Errorf("help output %q does not list update command", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestExecuteVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Execute(
		context.Background(),
		[]string{"version"},
		BuildInfo{Version: "1.2.3", Commit: "abc123", BuiltAt: "2026-08-26T12:00:00Z"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)

	if exitCode != ExitSuccess {
		t.Fatalf("Execute() exit code = %d, want %d; stderr = %q", exitCode, ExitSuccess, stderr.String())
	}
	const expected = "garga 1.2.3 (commit: abc123, built: 2026-08-26T12:00:00Z)\n"
	if stdout.String() != expected {
		t.Errorf("version output = %q, want %q", stdout.String(), expected)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestExecuteVersionRejectsArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	const secretCanary = "must-not-leak"

	exitCode := Execute(
		context.Background(),
		[]string{"version", secretCanary},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)

	if exitCode != ExitInvalidInput {
		t.Fatalf("Execute() exit code = %d, want %d", exitCode, ExitInvalidInput)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if strings.Contains(stderr.String(), secretCanary) {
		t.Errorf("stderr leaks rejected argument: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid command or arguments") {
		t.Errorf("stderr = %q, want safe argument validation error", stderr.String())
	}
}

func TestExecuteVersionUsesSafeDefaults(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Execute(context.Background(), []string{"version"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)

	if exitCode != ExitSuccess {
		t.Fatalf("Execute() exit code = %d, want %d; stderr = %q", exitCode, ExitSuccess, stderr.String())
	}
	const expected = "garga dev (commit: none, built: unknown)\n"
	if stdout.String() != expected {
		t.Errorf("version output = %q, want %q", stdout.String(), expected)
	}
}

func TestExecuteVersionClassifiesOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	const sensitiveCause = "writer failure with sensitive detail"

	exitCode := Execute(
		context.Background(),
		[]string{"version"},
		BuildInfo{},
		strings.NewReader(""),
		failingWriter{err: errors.New(sensitiveCause)},
		&stderr,
	)

	if exitCode != ExitInternalError {
		t.Fatalf("Execute() exit code = %d, want %d", exitCode, ExitInternalError)
	}
	if strings.Contains(stderr.String(), sensitiveCause) {
		t.Errorf("stderr leaks internal error cause: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "write version information") {
		t.Errorf("stderr = %q, want safe output failure message", stderr.String())
	}
}
