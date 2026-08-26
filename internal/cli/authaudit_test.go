package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/credential/audit"
)

func TestAuthAuditHelpDocumentsBoundedStdinAudit(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-audit", "--help"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	help := stdout.String()
	if !strings.Contains(help, "--credentials-stdin") {
		t.Fatalf("help missing stdin flag: %s", help)
	}
	if strings.Contains(help, "--password string") {
		t.Fatalf("help advertised a command-line password flag: %s", help)
	}
	if !strings.Contains(help, "process listings") || !strings.Contains(help, "attempt ceiling") {
		t.Fatalf("help missing safety text: %s", help)
	}
}

func TestAuthAuditDoesNotRegisterPasswordFlag(t *testing.T) {
	t.Parallel()

	root := NewRootCommand(BuildInfo{})
	cmd, _, err := root.Find([]string{"auth-audit"})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if cmd.Flags().Lookup("password") != nil {
		t.Fatal("auth-audit registered a --password flag")
	}
}

func TestScanCommandIsNotRegistered(t *testing.T) {
	t.Parallel()

	root := NewRootCommand(BuildInfo{})
	cmd, _, err := root.Find([]string{"scan"})
	if err == nil && cmd != nil && cmd.Name() == "scan" {
		t.Fatalf("scan must not be registered without proving it has no audit call path; found %q", cmd.Use)
	}
}

func TestScanSourcesDoNotCallAuditEngine(t *testing.T) {
	t.Parallel()

	matches, err := filepath.Glob("scan*.go")
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	for _, filename := range matches {
		content, readErr := os.ReadFile(filename)
		if readErr != nil {
			t.Fatalf("ReadFile(%s) error = %v", filename, readErr)
		}
		text := string(content)
		if strings.Contains(text, "internal/credential/audit") || strings.Contains(text, "runAuthAudit") {
			t.Fatalf("%s references the credential audit engine", filename)
		}
	}
}

func TestAuthAuditRequiresCredentialsStdin(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"auth-audit", "http://127.0.0.1:9200"},
		BuildInfo{},
		strings.NewReader("basic alice "+canary+"\n"),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if strings.Contains(stdout.String(), canary) || strings.Contains(stderr.String(), canary) {
		t.Fatalf("output leaked canary: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestAuthAuditStopsOnSuccess(t *testing.T) {
	const canary = "credential-canary"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		count := requests.Add(1)
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/_security/_authenticate") {
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		if count == 1 {
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(writer, `{"error":"`+canary+`"}`)
			return
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
	input := "basic alice " + canary + "-1\nbasic bob " + canary + "-2\nbasic carol " + canary + "-3\n"
	exitCode := Execute(
		context.Background(),
		[]string{"auth-audit", server.URL, "--credentials-stdin"},
		BuildInfo{Version: "test"},
		strings.NewReader(input),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
	output := stdout.String()
	if !strings.Contains(output, string(credential.OutcomeInvalid)) || !strings.Contains(output, string(credential.OutcomeValid)) {
		t.Fatalf("stdout = %q", output)
	}
	if !strings.Contains(output, "reason="+string(audit.StopSuccess)) {
		t.Fatalf("stdout missing stop reason: %q", output)
	}
	if strings.Contains(output, canary) || strings.Contains(stderr.String(), canary) {
		t.Fatalf("output leaked canary: stdout=%q stderr=%q", output, stderr.String())
	}
}
