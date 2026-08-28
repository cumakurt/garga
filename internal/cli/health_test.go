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
	artifacts, err := filepath.Glob(filepath.Join(reportDirectory, "garga-health-*.pdf"))
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("timestamped PDF artifacts = %v, error = %v", artifacts, err)
	}
	htmlArtifacts, err := filepath.Glob(filepath.Join(reportDirectory, "garga-health-*.html"))
	if err != nil || len(htmlArtifacts) != 0 {
		t.Fatalf("default health wrote HTML artifacts = %v, error = %v", htmlArtifacts, err)
	}
	info, err := os.Stat(artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact permissions = %o", info.Mode().Perm())
	}
	artifact, err := os.ReadFile(artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(artifact, []byte("%PDF")) {
		t.Fatal("health artifact is not a PDF")
	}
	for _, expected := range []string{"Elasticsearch Health Check and Assessment", "Top risks", "Prioritized action plan", "Field", "https://www.linkedin.com/in/cuma-kurt-34414917/", "https://github.com/cumakurt"} {
		if !bytes.Contains(artifact, []byte(expected)) {
			t.Fatalf("PDF artifact does not contain %q", expected)
		}
	}
	if bytes.Contains(artifact, []byte("credential-canary")) {
		t.Fatal("PDF artifact leaked sensitive evidence")
	}
	if !strings.Contains(stderr.String(), "PDF health report written to") {
		t.Fatalf("stderr missing PDF notice: %q", stderr.String())
	}
	mu.Lock()
	defer mu.Unlock()
	for path, method := range methods {
		if method != http.MethodGet {
			t.Fatalf("%s used %s", path, method)
		}
	}
}

func TestHealthHtmlReportFlagWritesHTMLAlongsidePDF(t *testing.T) {
	reportDirectory := t.TempDir()
	t.Chdir(reportDirectory)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status, payload := healthCLIResponse(request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, payload)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"health", server.URL, "--format", "json", "--html-report", "--requests-per-second", "100"}, BuildInfo{Version: "test"}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("Execute() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	pdfs, err := filepath.Glob(filepath.Join(reportDirectory, "garga-health-*.pdf"))
	if err != nil || len(pdfs) != 1 {
		t.Fatalf("PDF artifacts = %v, error = %v", pdfs, err)
	}
	htmls, err := filepath.Glob(filepath.Join(reportDirectory, "garga-health-*.html"))
	if err != nil || len(htmls) != 1 {
		t.Fatalf("HTML artifacts = %v, error = %v", htmls, err)
	}
	if !strings.Contains(stderr.String(), "PDF health report written to") || !strings.Contains(stderr.String(), "HTML health report written to") {
		t.Fatalf("stderr missing dual notices: %q", stderr.String())
	}
}

func TestAssessUsesAuthenticatedGETOnlyRuntimeAndWritesAssessmentArtifact(t *testing.T) {
	reportDirectory := t.TempDir()
	t.Chdir(reportDirectory)
	signatureDirectory := t.TempDir()
	signature := `schema_version: "0.1"
id: garga.vuln.assess-fixture
title: Authenticated assessment fixture
severity: high
cve: [CVE-2099-10002]
product: elasticsearch
affected: [">=8.19.0 <8.20.0"]
detection: version
remediation: Upgrade Elasticsearch.
`
	if err := os.WriteFile(filepath.Join(signatureDirectory, "fixture.yaml"), []byte(signature), 0o600); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Body != nil && request.Body != http.NoBody {
			t.Errorf("unsafe request: %s %s", request.Method, request.URL.Path)
		}
		username, password, ok := request.BasicAuth()
		if !ok || username != "elastic" || password != "credential-canary" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		requests++
		mu.Unlock()
		status, payload := healthCLIResponse(request.URL.Path)
		if request.URL.Path == "/_security/_authenticate" {
			status, payload = http.StatusOK, `{"username":"elastic","authentication_type":"realm"}`
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, payload)
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	exitCode := Execute(context.Background(), []string{"assess", server.URL, "--username", "elastic", "--password-stdin", "--insecure", "--format", "json", "--signatures", signatureDirectory, "--requests-per-second", "100"}, BuildInfo{Version: "test"}, strings.NewReader("credential-canary\n"), &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("Execute() exit = %d, stderr = %q", exitCode, stderr.String())
	}
	var document struct {
		Metadata struct {
			AssessmentMode bool `json:"assessment_mode"`
		} `json:"metadata"`
		Findings []healthmodel.Finding `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("decode assessment: %v", err)
	}
	if !document.Metadata.AssessmentMode {
		t.Fatal("assessment metadata was not enabled")
	}
	found := false
	for _, finding := range document.Findings {
		if finding.ID == "garga.vuln.assess-fixture" {
			found = true
		}
	}
	if !found {
		t.Fatalf("assessment vulnerability missing: %#v", document.Findings)
	}
	artifacts, err := filepath.Glob(filepath.Join(reportDirectory, "garga-assessment-*.pdf"))
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("assessment artifacts = %v, error = %v", artifacts, err)
	}
	payload, err := os.ReadFile(artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte("Elasticsearch Security and Health Assessment")) || bytes.Contains(payload, []byte("credential-canary")) {
		t.Fatal("assessment PDF title or redaction contract failed")
	}
	if !strings.Contains(stderr.String(), "PDF assessment report written to") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if requests == 0 {
		t.Fatal("assessment made no authenticated requests")
	}
}

func TestAssessHelpDocumentsExplicitSecurityBoundary(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if exitCode := Execute(context.Background(), []string{"assess", "--help"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr); exitCode != ExitSuccess {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr.String())
	}
	for _, expected := range []string{"--signatures", "--password-stdin", "GET-only", "runtime-applicable", "No state-changing"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("help missing %q", expected)
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
	for _, needle := range []string{"--profile", "--deep", "--format", "--fail-on", "--baseline", "--snapshot-out", "--password-stdin", "--api-key-stdin", "--bearer-token-stdin", "--allow-plaintext-auth", "--max-response-bytes", "--html-report", "GET", "10/11/12", "PDF"} {
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
	case "/_nodes/_all/os,process,jvm,plugins":
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
