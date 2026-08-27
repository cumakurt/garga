package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/checks"
	"github.com/cumakurt/garga/internal/model"
)

func TestVulnHelpDocumentsSignatureMatching(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"vuln", "--help"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	help := stdout.String()
	for _, needle := range []string{"--signatures", "--file", "potential", "GET", "exploit", "bundled", "--no-progress"} {
		if !strings.Contains(help, needle) {
			t.Errorf("help missing %q: %s", needle, help)
		}
	}
	if strings.Contains(help, "--password") {
		t.Fatalf("help advertised a password flag: %s", help)
	}
}

func TestVulnDoesNotRegisterPasswordFlag(t *testing.T) {
	t.Parallel()

	root := NewRootCommand(BuildInfo{})
	cmd, _, err := root.Find([]string{"vuln"})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if cmd.Name() != "vuln" {
		t.Fatalf("command = %q", cmd.Name())
	}
	if cmd.Flags().Lookup("password") != nil {
		t.Fatal("vuln registered a --password flag")
	}
}

func TestVulnRequiresTargets(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"vuln", "--signatures", "/tmp/signatures"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "target argument or --file") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestVulnJSONLSignatureFinding(t *testing.T) {
	clearProxyEnv(t)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Errorf("method = %q", request.Method)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		writer.WriteHeader(http.StatusOK)
		body := strings.Replace(elasticsearchScanBody, "8.19.19", "9.4.4", 1)
		if request.URL.Path == "/" || request.URL.Path == "" {
			_, _ = io.WriteString(writer, body)
			return
		}
		_, _ = io.WriteString(writer, `{"status":"green"}`)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	sourceYAML, err := os.ReadFile(filepath.Join("..", "vulnerability", "testdata", "valid", "example-version-only-94.yaml"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "example-version-only-94.yaml"), sourceYAML, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "garga.yaml")
	if err := os.WriteFile(configPath, []byte("scanner:\n  retries: 0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"vuln", server.URL, "--signatures", dir, "--format", "jsonl", "--config", configPath},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q stdout = %q", exitCode, stderr.String(), stdout.String())
	}

	ids := map[string]bool{}
	decoder := json.NewDecoder(&stdout)
	for {
		var finding model.Finding
		if err := decoder.Decode(&finding); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("Decode() error = %v stdout = %s", err, stdout.String())
		}
		ids[finding.CheckID] = true
	}
	if !ids["garga.vuln.example-version-only-94"] {
		t.Fatalf("missing signature finding: %v", ids)
	}
	if ids[checks.CheckTLSNotEnabled] {
		t.Fatalf("tls check leaked: %v", ids)
	}
}

func TestVulnInterruptedContext(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sourceYAML, err := os.ReadFile(filepath.Join("..", "vulnerability", "testdata", "valid", "example-version-only-94.yaml"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "example-version-only-94.yaml"), sourceYAML, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		ctx,
		[]string{"vuln", "http://127.0.0.1:1", "--signatures", dir},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInterrupted {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
}
