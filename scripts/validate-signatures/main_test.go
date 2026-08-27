package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunValidatesFixtureDirectory(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	dir := filepath.Join("..", "..", "internal", "vulnerability", "testdata", "valid")
	if code := run([]string{dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d; stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "validated 5 signatures") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunRejectsInvalidDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	source := filepath.Join("..", "..", "internal", "vulnerability", "testdata", "invalid", "missing-id.yaml")
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "missing-id.yaml"), contents, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{dir}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d; stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "missing-id.yaml") {
		t.Fatalf("stderr missing file context: %q", stderr.String())
	}
}

func TestRunRequiresDirectoryArgument(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
