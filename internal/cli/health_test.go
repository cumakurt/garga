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

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func TestHealthCommandWritesStableJSONAndUsesGETOnly(t *testing.T) {
	reportDirectory := t.TempDir()
	t.Chdir(reportDirectory)
	var mu sync.Mutex
	methods := make(map[string]string)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		methods[request.URL.Path] = request.Method
		mu.Unlock()
		if request.Body != nil && request.Body != http.NoBody || request.ContentLength > 0 {
			t.Errorf("request %s included a body", request.URL.Path)
		}
		status, payload := healthCLIResponse(request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, payload)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"health", server.URL, "--format", "json", "--requests-per-second", "100", "--concurrency", "4", "--profile", "production"}, BuildInfo{Version: "test"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("Execute() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	var document struct {
		SchemaVersion string `json:"schema_version"`
		Summary       struct {
			HealthScore int `json:"health_score"`
		} `json:"summary"`
		Metadata struct {
			APIRequests int `json:"api_requests"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("decode output: %v\n%s", err, stdout.String())
	}
	if document.SchemaVersion != "1.0" || document.Metadata.APIRequests == 0 || document.Summary.HealthScore >= 100 {
		t.Fatalf("health document = %#v", document)
	}
	artifacts, err := filepath.Glob(filepath.Join(reportDirectory, "garga-health-*.html"))
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("timestamped HTML artifacts = %v, error = %v", artifacts, err)
	}
	artifact, err := os.ReadFile(artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"garga logo", "Executive Summary", "Detailed Findings", "Assessment Coverage", "https://www.linkedin.com/in/cuma-kurt-34414917/", "https://github.com/cumakurt"} {
		if !bytes.Contains(artifact, []byte(expected)) {
			t.Fatalf("HTML artifact does not contain %q", expected)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for path, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("%s used %s", path, method)
		}
	}
}

func TestHealthCommandRefusesCredentialOverHTTPAndRedactsIt(t *testing.T) {
	t.Chdir(t.TempDir())
	const canary = "credential-canary"
	t.Setenv("ESHEALTH_USERNAME", "elastic")
	t.Setenv("ESHEALTH_PASSWORD", canary)
	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"health", "http://127.0.0.1:9200"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitInvalidInput {
		t.Fatalf("Execute() exit = %d, want %d", exitCode, ExitInvalidInput)
	}
	if strings.Contains(stdout.String(), canary) || strings.Contains(stderr.String(), canary) {
		t.Fatalf("credential leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestHealthFailOnHighUsesAutomationExitCode(t *testing.T) {
	t.Chdir(t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status, payload := healthCLIResponse(request.URL.Path)
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, payload)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"health", server.URL, "--format", "json", "--requests-per-second", "100", "--fail-on", "high"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitHealthHigh {
		t.Fatalf("Execute() exit = %d, want %d; stderr=%q", exitCode, ExitHealthHigh, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatal("health report was not written before severity exit")
	}
}

func TestHealthHelpDocumentsSafetyAndFlags(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"health", "--help"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	help := stdout.String()
	for _, needle := range []string{"--profile", "--deep", "--format", "--fail-on", "--baseline", "--snapshot-out", "--password-stdin", "--api-key-stdin", "--bearer-token-stdin", "--allow-plaintext-auth", "--max-response-bytes", "GET", "10/11/12"} {
		if !strings.Contains(help, needle) {
			t.Errorf("help missing %q", needle)
		}
	}
	if strings.Contains(help, "--password string") {
		t.Fatalf("help advertised a command-line password flag: %s", help)
	}
}

func TestHealthInvalidFailOnExitsInvalidInput(t *testing.T) {
	t.Chdir(t.TempDir())
	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"health", "http://127.0.0.1:9200", "--fail-on", "nope"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitInvalidInput {
		t.Fatalf("Execute() exit = %d, want %d; stderr=%q", exitCode, ExitInvalidInput, stderr.String())
	}
}

func TestHealthDeepEnablesHighCostCollectors(t *testing.T) {
	t.Chdir(t.TempDir())
	var mu sync.Mutex
	paths := make(map[string]struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		paths[request.URL.Path] = struct{}{}
		mu.Unlock()
		status, payload := healthCLIResponse(request.URL.Path)
		if request.URL.Path == "/_snapshot/_all" {
			payload = `{}`
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, payload)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"health", server.URL, "--deep", "--format", "json", "--requests-per-second", "100"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("Execute() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/_ilm/explain", "/_tasks", "/_data_stream", "/_snapshot/_all", "/_nodes/settings"} {
		if _, ok := paths[path]; !ok {
			t.Errorf("deep collection missed %s", path)
		}
	}
}

func TestHealthSnapshotOutAndBaselineRoundTrip(t *testing.T) {
	directory := t.TempDir()
	t.Chdir(directory)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status, payload := healthCLIResponse(request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, payload)
	}))
	defer server.Close()
	baselinePath := filepath.Join(directory, "baseline.json")
	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"health", server.URL, "--format", "json", "--snapshot-out", baselinePath, "--requests-per-second", "100"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("snapshot-out exit = %d, stderr=%q", exitCode, stderr.String())
	}
	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("baseline was not written: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	exitCode = Execute(context.Background(), []string{"health", server.URL, "--format", "json", "--baseline", baselinePath, "--requests-per-second", "100"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("baseline exit = %d, stderr=%q", exitCode, stderr.String())
	}
}

func TestHealthFailOnWarningUsesAutomationExitCode(t *testing.T) {
	t.Chdir(t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status, payload := healthCLIResponse(request.URL.Path)
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, payload)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"health", server.URL, "--format", "json", "--requests-per-second", "100", "--fail-on", "warning"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitHealthHigh {
		t.Fatalf("Execute() exit = %d, want %d for high TLS finding; stderr=%q", exitCode, ExitHealthHigh, stderr.String())
	}
}

func TestHealthAuthenticationFailureUsesHealthFailureCode(t *testing.T) {
	t.Chdir(t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"health", server.URL, "--format", "json"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitHealthFailure {
		t.Fatalf("Execute() exit = %d, want %d; stderr=%q", exitCode, ExitHealthFailure, stderr.String())
	}
}

func TestHealthFailureCodeUsesDedicatedSeverityExits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		highest   healthmodel.Severity
		threshold healthmodel.Severity
		want      int
	}{
		{healthmodel.SeverityLow, healthmodel.SeverityMedium, 0},
		{healthmodel.SeverityMedium, healthmodel.SeverityMedium, ExitHealthWarning},
		{healthmodel.SeverityHigh, healthmodel.SeverityMedium, ExitHealthHigh},
		{healthmodel.SeverityHigh, healthmodel.SeverityHigh, ExitHealthHigh},
		{healthmodel.SeverityCritical, healthmodel.SeverityHigh, ExitHealthCritical},
		{healthmodel.SeverityCritical, healthmodel.SeverityCritical, ExitHealthCritical},
		{healthmodel.SeverityMedium, healthmodel.SeverityHigh, 0},
	}
	for _, testCase := range cases {
		code, _ := healthFailureCode([]healthmodel.Finding{{Severity: testCase.highest}}, testCase.threshold)
		if code != testCase.want {
			t.Errorf("highest=%s threshold=%s code=%d, want %d", testCase.highest, testCase.threshold, code, testCase.want)
		}
	}
}

func healthCLIResponse(path string) (int, string) {
	switch path {
	case "/":
		return http.StatusOK, `{"cluster_name":"fixture","cluster_uuid":"uuid","version":{"number":"8.19.19","build_flavor":"default","build_type":"docker","build_hash":"hash","lucene_version":"9.12.3","minimum_wire_compatibility_version":"7.17.0","minimum_index_compatibility_version":"7.0.0"},"tagline":"You Know, for Search"}`
	case "/_cluster/health":
		return http.StatusOK, `{"status":"green","number_of_nodes":3,"number_of_data_nodes":3,"active_shards_percent_as_number":100,"unassigned_shards":0}`
	case "/_cluster/stats":
		return http.StatusOK, `{"indices":{"count":0,"shards":{"total":0},"docs":{"count":0},"store":{"size_in_bytes":0}},"nodes":{"count":{"total":3,"data":3}}}`
	case "/_nodes/_all/os,process,jvm":
		return http.StatusOK, `{"nodes":{"node-1":{"name":"data-1","roles":["master","data_hot"]},"node-2":{"name":"data-2","roles":["master","data_hot"]},"node-3":{"name":"data-3","roles":["master","data_hot"]}}}`
	case "/_nodes/stats/jvm,os,process,fs,thread_pool,breaker,indices,indexing_pressure":
		return http.StatusOK, `{"nodes":{"node-1":{"name":"data-1","roles":["master","data_hot"],"fs":{"total":{"total_in_bytes":100,"available_in_bytes":50}}},"node-2":{"name":"data-2","roles":["master","data_hot"],"fs":{"total":{"total_in_bytes":100,"available_in_bytes":50}}},"node-3":{"name":"data-3","roles":["master","data_hot"],"fs":{"total":{"total_in_bytes":100,"available_in_bytes":50}}}}}`
	case "/_cat/indices", "/_cat/shards":
		return http.StatusOK, `[]`
	case "/_security/_authenticate":
		return http.StatusUnauthorized, `{}`
	default:
		return http.StatusOK, `{}`
	}
}
