package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/credential"
)

func TestAuthCheckHelpDocumentsStdinSecrets(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-check", "--help"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	help := stdout.String()
	if !strings.Contains(help, "--password-stdin") || !strings.Contains(help, "--api-key-stdin") {
		t.Fatalf("help missing stdin flags: %s", help)
	}
	if strings.Contains(help, "--password string") {
		t.Fatalf("help advertised a command-line password flag: %s", help)
	}
	if !strings.Contains(help, "process listings") {
		t.Fatalf("help missing password-flag warning: %s", help)
	}
}

func TestAuthCheckDoesNotRegisterPasswordFlag(t *testing.T) {
	t.Parallel()

	root := NewRootCommand(BuildInfo{})
	cmd, _, err := root.Find([]string{"auth-check"})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if cmd.Flags().Lookup("password") != nil {
		t.Fatal("auth-check registered a --password flag")
	}
}

func TestAuthCheckRejectsMissingSecretFlags(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-check", "http://127.0.0.1:9200"},
		BuildInfo{},
		strings.NewReader(canary+"\n"),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stderr.String(), canary) {
		t.Fatalf("stderr leaked canary: %q", stderr.String())
	}
}

func TestAuthCheckRejectsMixedMechanisms(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-check", "http://127.0.0.1:9200", "--username", "alice", "--password-stdin", "--api-key-stdin"},
		BuildInfo{},
		strings.NewReader(canary+"\n"),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if strings.Contains(stderr.String(), canary) {
		t.Fatalf("stderr leaked canary: %q", stderr.String())
	}
}

func TestAuthCheckVerifiesBasicAuth(t *testing.T) {
	const canary = "credential-canary"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/_security/_authenticate") {
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, `{"username":"`+canary+`"}`)
	}))
	defer server.Close()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-check", server.URL, "--username", "alice", "--password-stdin"},
		BuildInfo{Version: "test"},
		strings.NewReader(canary+"\n"),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	want := fmt.Sprintf("auth-check: %s mechanism=%s status=%d\n", credential.OutcomeValid, credential.KindBasic, http.StatusOK)
	if stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	if strings.Contains(stdout.String(), canary) || strings.Contains(stderr.String(), canary) {
		t.Fatalf("output leaked canary: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "auth-check completed") {
		t.Fatalf("default log level emitted debug noise: %q", stderr.String())
	}
}

func TestAuthCheckReportsInvalidCredential(t *testing.T) {
	const canary = "credential-canary"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, `{"error":"`+canary+`"}`)
	}))
	defer server.Close()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-check", server.URL, "--api-key-stdin"},
		BuildInfo{Version: "test"},
		strings.NewReader(canary+"\n"),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), string(credential.OutcomeInvalid)) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stdout.String(), canary) || strings.Contains(stderr.String(), canary) {
		t.Fatalf("output leaked canary: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestAuthCheckDebugLogsOmitSecrets(t *testing.T) {
	const canary = "credential-canary"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, `{"username":"alice"}`)
	}))
	defer server.Close()

	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")

	configPath := filepath.Join(t.TempDir(), "garga.yaml")
	if err := os.WriteFile(configPath, []byte("logging:\n  level: debug\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-check", server.URL, "--username", "alice", "--password-stdin", "--config", configPath},
		BuildInfo{Version: "test"},
		strings.NewReader(canary+"\n"),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "auth-check completed") {
		t.Fatalf("debug logs missing completion record: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), canary) || strings.Contains(stderr.String(), server.URL) {
		t.Fatalf("debug logs leaked secret or target: %q", stderr.String())
	}
}
