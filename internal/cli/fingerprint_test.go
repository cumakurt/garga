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
	"sync"
	"testing"

	"github.com/cumakurt/garga/internal/app"
)

func TestFingerprintHelpDocumentsReadOnlyIdentity(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"fingerprint", "--help"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	help := stdout.String()
	for _, needle := range []string{"--file", "--format", "--insecure", "--threshold", "--no-progress", "GET /", "does not discover extra APIs"} {
		if !strings.Contains(help, needle) {
			t.Errorf("help missing %q: %s", needle, help)
		}
	}
	if strings.Contains(help, "--password") || strings.Contains(help, "--signatures") {
		t.Fatalf("help advertised scan-only flags: %s", help)
	}
}

func TestFingerprintDoesNotRegisterPasswordFlag(t *testing.T) {
	t.Parallel()

	root := NewRootCommand(BuildInfo{})
	cmd, _, err := root.Find([]string{"fingerprint"})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if cmd.Name() != "fingerprint" {
		t.Fatalf("command = %q", cmd.Name())
	}
	if cmd.Flags().Lookup("password") != nil {
		t.Fatal("fingerprint registered a --password flag")
	}
}

func TestFingerprintRequiresTargets(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"fingerprint"},
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

func TestFingerprintJSONLConfirmedCluster(t *testing.T) {
	clearProxyEnv(t)

	var mu sync.Mutex
	var methods []string
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		methods = append(methods, request.Method)
		paths = append(paths, request.URL.Path)
		mu.Unlock()
		if request.Method != http.MethodGet {
			t.Errorf("method = %q", request.Method)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, elasticsearchScanBody)
	}))
	t.Cleanup(server.Close)

	configPath := filepath.Join(t.TempDir(), "garga.yaml")
	if err := os.WriteFile(configPath, []byte("scanner:\n  retries: 0\nlogging:\n  level: debug\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"fingerprint", server.URL, "--format", "jsonl", "--config", configPath},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}

	var identity app.Identity
	if err := json.Unmarshal(stdout.Bytes(), &identity); err != nil {
		t.Fatalf("Unmarshal() error = %v stdout = %s", err, stdout.String())
	}
	if !identity.Detected || identity.Version != "8.19.19" {
		t.Fatalf("identity = %#v", identity)
	}
	mu.Lock()
	gotMethods := append([]string(nil), methods...)
	gotPaths := append([]string(nil), paths...)
	mu.Unlock()
	if len(gotMethods) != 1 || gotMethods[0] != http.MethodGet || gotPaths[0] != "/" {
		t.Fatalf("requests methods=%v paths=%v", gotMethods, gotPaths)
	}
	if strings.Contains(stderr.String(), server.URL) {
		t.Fatalf("debug logs leaked target: %q", stderr.String())
	}
}

func TestFingerprintPartialFailure(t *testing.T) {
	clearProxyEnv(t)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, elasticsearchScanBody)
	}))
	t.Cleanup(server.Close)

	configPath := filepath.Join(t.TempDir(), "garga.yaml")
	if err := os.WriteFile(configPath, []byte("scanner:\n  retries: 0\n  connect_timeout: 250ms\n  request_timeout: 1s\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"fingerprint", server.URL, "http://127.0.0.1:1", "--format", "jsonl", "--config", configPath},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitPartialFailure {
		t.Fatalf("exit code = %d; stderr = %q stdout = %q", exitCode, stderr.String(), stdout.String())
	}
}

func TestFingerprintRejectsHTMLFormat(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"fingerprint", "http://127.0.0.1:9200", "--format", "html"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "fingerprint format is not supported") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestFingerprintInterruptedContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		ctx,
		[]string{"fingerprint", "http://127.0.0.1:1"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInterrupted {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
}
