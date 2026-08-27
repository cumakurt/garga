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

func TestScanHelpDocumentsReadOnlyAssessment(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"scan", "--help"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	help := stdout.String()
	for _, needle := range []string{"--file", "--format", "--insecure", "--signatures", "--no-signatures", "--no-progress", "GET", "does not send credentials", "timestamped"} {
		if !strings.Contains(help, needle) {
			t.Errorf("help missing %q: %s", needle, help)
		}
	}
	if strings.Contains(help, "--password") {
		t.Fatalf("help advertised a password flag: %s", help)
	}
}

func TestScanDoesNotRegisterPasswordFlag(t *testing.T) {
	t.Parallel()

	root := NewRootCommand(BuildInfo{})
	cmd, _, err := root.Find([]string{"scan"})
	if err != nil {
		t.Fatalf("Find() error = %v", err)
	}
	if cmd.Name() != "scan" {
		t.Fatalf("command = %q", cmd.Name())
	}
	if cmd.Flags().Lookup("password") != nil {
		t.Fatal("scan registered a --password flag")
	}
}

func TestScanRequiresTargets(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"scan"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, ExitInvalidInput, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "target argument or --file") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestScanRejectsInvalidTarget(t *testing.T) {
	t.Parallel()

	const canary = "secret-target-canary"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"scan", "http://example.com/?q=" + canary},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if strings.Contains(stderr.String(), canary) {
		t.Errorf("stderr leaked canary: %q", stderr.String())
	}
}

func TestScanJSONLFindsOpenHTTPCluster(t *testing.T) {
	clearProxyEnv(t)
	t.Chdir(t.TempDir())

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Errorf("method = %q", request.Method)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		if strings.HasSuffix(request.URL.Path, "/_security/_authenticate") {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.WriteHeader(http.StatusOK)
		if request.URL.Path == "/" || request.URL.Path == "" {
			_, _ = io.WriteString(writer, elasticsearchScanBody)
			return
		}
		_, _ = io.WriteString(writer, `{"status":"green"}`)
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
		[]string{"scan", server.URL, "--format", "jsonl", "--config", configPath},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
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
	if !ids[checks.CheckTLSNotEnabled] || !ids[checks.CheckExposureAnonymousAccess] {
		t.Fatalf("findings = %v", ids)
	}
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.Contains(line, `"level":"DEBUG"`) && strings.Contains(line, server.URL) {
			t.Fatalf("debug logs leaked target: %q", stderr.String())
		}
	}
}

func TestScanCSVPrintsDetectionNotice(t *testing.T) {
	clearProxyEnv(t)
	t.Chdir(t.TempDir())

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		if strings.HasSuffix(request.URL.Path, "/_security/_authenticate") {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.WriteHeader(http.StatusOK)
		if request.URL.Path == "/" || request.URL.Path == "" {
			_, _ = io.WriteString(writer, elasticsearchScanBody)
			return
		}
		_, _ = io.WriteString(writer, `{"status":"green"}`)
	}))
	t.Cleanup(server.Close)

	configPath := filepath.Join(t.TempDir(), "garga.yaml")
	if err := os.WriteFile(configPath, []byte("scanner:\n  retries: 0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"scan", server.URL, "--format", "csv", "--no-signatures", "--config", configPath},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "check_id") || !strings.Contains(stdout.String(), "description") {
		t.Fatalf("csv stdout missing columns: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "garga.tls.not_enabled") {
		t.Fatalf("csv missing tls finding: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "HIGH") || !strings.Contains(stderr.String(), "garga.tls.not_enabled") {
		t.Fatalf("stderr missing detection summary: %q", stderr.String())
	}
}

func TestScanCSVReportsBundledCVE(t *testing.T) {
	clearProxyEnv(t)
	t.Chdir(t.TempDir())

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		if strings.HasSuffix(request.URL.Path, "/_security/_authenticate") {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.WriteHeader(http.StatusOK)
		body := strings.Replace(elasticsearchScanBody, "8.19.19", "8.8.0", 1)
		if request.URL.Path == "/" || request.URL.Path == "" {
			_, _ = io.WriteString(writer, body)
			return
		}
		_, _ = io.WriteString(writer, `{"status":"green"}`)
	}))
	t.Cleanup(server.Close)

	configPath := filepath.Join(t.TempDir(), "garga.yaml")
	if err := os.WriteFile(configPath, []byte("scanner:\n  retries: 0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"scan", server.URL, "--format", "csv", "--config", configPath},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	csvOut := stdout.String()
	if !strings.Contains(csvOut, "cve,cvss,description") {
		t.Fatalf("csv missing detection columns: %q", csvOut)
	}
	if !strings.Contains(csvOut, "CVE-2023-31418") {
		t.Fatalf("csv missing bundled CVE: %q", csvOut)
	}
	if !strings.Contains(stderr.String(), "CVE-2023-31418") {
		t.Fatalf("stderr missing CVE detection summary: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "8.8.0") {
		t.Fatalf("stderr missing detected version: %q", stderr.String())
	}
}

func TestScanRejectsNoSignaturesWithSignatures(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"scan", "http://127.0.0.1:9200", "--no-signatures", "--signatures", "/tmp/signatures"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, ExitInvalidInput, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--no-signatures cannot be combined with --signatures") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestScanFileAndPartialFailure(t *testing.T) {
	clearProxyEnv(t)
	t.Chdir(t.TempDir())

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, elasticsearchScanBody)
	}))
	t.Cleanup(server.Close)

	filePath := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(filePath, []byte(server.URL+"\nhttp://127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "garga.yaml")
	if err := os.WriteFile(configPath, []byte("scanner:\n  retries: 0\n  connect_timeout: 250ms\n  request_timeout: 1s\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"scan", "--file", filePath, "--format", "jsonl", "--config", configPath},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitPartialFailure {
		t.Fatalf("exit code = %d, want %d; stderr = %q stdout = %q", exitCode, ExitPartialFailure, stderr.String(), stdout.String())
	}
	if !strings.Contains(stderr.String(), "partial operational failures") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestScanInterruptedContext(t *testing.T) {
	t.Chdir(t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		ctx,
		[]string{"scan", "http://127.0.0.1:1"},
		BuildInfo{},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitInterrupted {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, ExitInterrupted, stderr.String())
	}
}

func TestScanBindsFormatFromConfig(t *testing.T) {
	clearProxyEnv(t)
	t.Chdir(t.TempDir())

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "ok")
	}))
	t.Cleanup(server.Close)

	configPath := filepath.Join(t.TempDir(), "garga.yaml")
	if err := os.WriteFile(configPath, []byte("output:\n  format: jsonl\nscanner:\n  retries: 0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"scan", server.URL, "--config", configPath},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("non-elasticsearch scan wrote findings: %q", stdout.String())
	}
}

func TestScanDefaultLogLevelOmitsDebugAndInfoRecords(t *testing.T) {
	clearProxyEnv(t)
	t.Chdir(t.TempDir())

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "ok")
	}))
	t.Cleanup(server.Close)

	configPath := filepath.Join(t.TempDir(), "garga.yaml")
	if err := os.WriteFile(configPath, []byte("scanner:\n  retries: 0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"scan", server.URL, "--format", "jsonl", "--config", configPath},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	logs := stderr.String()
	if strings.Contains(logs, "scanner started") || strings.Contains(logs, "scanner finished") {
		t.Fatalf("default log level emitted info records: %q", logs)
	}
	if strings.Contains(logs, `"level":"DEBUG"`) || strings.Contains(logs, `"level":"debug"`) {
		t.Fatalf("default log level emitted debug records: %q", logs)
	}
}

func TestScanWritesTimestampedHTMLReport(t *testing.T) {
	clearProxyEnv(t)
	reportDirectory := t.TempDir()
	t.Chdir(reportDirectory)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		if strings.HasSuffix(request.URL.Path, "/_security/_authenticate") {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.WriteHeader(http.StatusOK)
		if request.URL.Path == "/" || request.URL.Path == "" {
			_, _ = io.WriteString(writer, elasticsearchScanBody)
			return
		}
		_, _ = io.WriteString(writer, `{"status":"green"}`)
	}))
	t.Cleanup(server.Close)

	configPath := filepath.Join(t.TempDir(), "garga.yaml")
	if err := os.WriteFile(configPath, []byte("scanner:\n  retries: 0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout, stderr bytes.Buffer
	exitCode := Execute(
		context.Background(),
		[]string{"scan", server.URL, "--format", "jsonl", "--no-signatures", "--config", configPath},
		BuildInfo{Version: "test"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"check_id":"garga.tls.not_enabled"`) {
		t.Fatalf("stdout lost jsonl findings: %q", stdout.String())
	}
	artifacts, err := filepath.Glob(filepath.Join(reportDirectory, "garga-scan-*.html"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("scan HTML artifacts = %v", artifacts)
	}
	info, err := os.Stat(artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact permissions = %o", info.Mode().Perm())
	}
	payload, err := os.ReadFile(artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	html := string(payload)
	for _, needle := range []string{
		"data:image/png;base64,",
		"garga logo",
		"Executive Summary",
		"Detailed Findings",
		"Why this appeared",
		"What it costs if ignored",
		"How to fix it",
		"Prioritized Action Plan",
		"garga.tls.not_enabled",
		"https://www.linkedin.com/in/cuma-kurt-34414917/",
		"https://github.com/cumakurt",
	} {
		if !strings.Contains(html, needle) {
			t.Errorf("artifact missing %q", needle)
		}
	}
	if strings.Contains(strings.ToLower(html), "<script") {
		t.Fatalf("scan HTML contains a script")
	}
	if !strings.Contains(stderr.String(), "HTML scan report written to") {
		t.Fatalf("stderr missing artifact notice: %q", stderr.String())
	}
}

func clearProxyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")
}

const elasticsearchScanBody = `{
  "name": "fixture-node",
  "cluster_name": "fixture-cluster",
  "cluster_uuid": "0000000000000000000000",
  "version": {
    "number": "8.19.19",
    "build_flavor": "default",
    "build_type": "docker",
    "build_hash": "0000000000000000000000000000000000000000",
    "build_date": "2026-08-01T00:00:00.000000000Z",
    "build_snapshot": false,
    "lucene_version": "9.12.0",
    "minimum_wire_compatibility_version": "7.17.0",
    "minimum_index_compatibility_version": "7.0.0"
  },
  "tagline": "You Know, for Search"
}`
