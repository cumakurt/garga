package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/capability"
	"github.com/cumakurt/garga/internal/checks"
	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/report"
	"github.com/cumakurt/garga/internal/target"
)

const elasticsearchRootBody = `{
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

func TestScanEmitsExposureFindingsForOpenHTTPCluster(t *testing.T) {
	clearProxyEnv(t)
	t.Chdir(t.TempDir())

	recorder := newMethodRecorder()
	server := httptest.NewServer(recorder.handler(openElasticsearchHandler()))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	result, err := Scan(context.Background(), testScanOptions(t, server.URL, &stdout))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Stats.Failed != 0 || result.Stats.Succeeded != 1 {
		t.Fatalf("stats succeeded=%d failed=%d", result.Stats.Succeeded, result.Stats.Failed)
	}

	ids := findingCheckIDs(t, stdout.Bytes())
	for _, id := range []string{
		checks.CheckTLSNotEnabled,
		checks.CheckExposureAnonymousAccess,
		checks.CheckExposureSecurityUnconfigured,
	} {
		if !ids[id] {
			t.Errorf("missing check %s in %v", id, ids)
		}
	}
	if ids[checks.CheckExposurePublicNetwork] {
		t.Errorf("loopback target classified as public: %v", ids)
	}

	assertGetOnlyAllowlisted(t, recorder.snapshot())
}

func TestScanSkipsCapabilityProbesForNonElasticsearch(t *testing.T) {
	clearProxyEnv(t)
	t.Chdir(t.TempDir())

	recorder := newMethodRecorder()
	server := httptest.NewServer(recorder.handler(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "<html><body>nginx</body></html>")
	})))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	result, err := Scan(context.Background(), testScanOptions(t, server.URL, &stdout))
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Findings != 0 {
		t.Fatalf("findings = %d, want 0; stdout = %s", result.Findings, stdout.String())
	}
	requests := recorder.snapshot()
	if len(requests) != 1 || requests[0].Method != http.MethodGet || requests[0].Path != "/" {
		t.Fatalf("requests = %#v, want a single GET /", requests)
	}
}

func TestScanRejectsEmptyTargetStream(t *testing.T) {
	t.Parallel()

	source, err := target.NewReaderSource(strings.NewReader("# none\n\n"), "cli")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	_, err = Scan(context.Background(), Options{
		Config: testConfig(),
		Source: source,
		Output: io.Discard,
		Format: report.FormatJSONL,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Scan() error = %v, want ErrInvalidInput", err)
	}
}

func TestScanRejectsInvalidSignatureDirectory(t *testing.T) {
	t.Parallel()

	source, err := target.NewReaderSource(strings.NewReader("http://127.0.0.1:9200\n"), "cli")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	_, err = Scan(context.Background(), Options{
		Config:       testConfig(),
		Source:       source,
		Output:       io.Discard,
		Format:       report.FormatJSONL,
		SignatureDir: filepath.Join(t.TempDir(), "missing"),
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Scan() error = %v, want ErrInvalidInput", err)
	}
}

func TestScanHonorsCancellation(t *testing.T) {
	t.Chdir(t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	source, err := target.NewReaderSource(strings.NewReader("http://127.0.0.1:1\n"), "cli")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	_, err = Scan(ctx, Options{
		Config: testConfig(),
		Source: source,
		Output: io.Discard,
		Format: report.FormatJSONL,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan() error = %v, want context.Canceled", err)
	}
}

func TestScanCountsUnreachableTargetsAsFailures(t *testing.T) {
	clearProxyEnv(t)
	t.Chdir(t.TempDir())

	recorder := newMethodRecorder()
	server := httptest.NewServer(recorder.handler(openElasticsearchHandler()))
	t.Cleanup(server.Close)

	input := server.URL + "\nhttp://127.0.0.1:1\n"
	source, err := target.NewReaderSource(strings.NewReader(input), "cli")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	result, err := Scan(context.Background(), Options{
		Config: testConfig(),
		Source: source,
		Output: io.Discard,
		Format: report.FormatJSONL,
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Stats.Succeeded != 1 || result.Stats.Failed != 1 {
		t.Fatalf("succeeded=%d failed=%d, want 1 and 1", result.Stats.Succeeded, result.Stats.Failed)
	}
	assertGetOnlyAllowlisted(t, recorder.snapshot())
}

func testScanOptions(t *testing.T, rawTarget string, output io.Writer) Options {
	t.Helper()
	source, err := target.NewReaderSource(strings.NewReader(rawTarget+"\n"), "cli")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	return Options{
		Config: testConfig(),
		Source: source,
		Output: output,
		Format: report.FormatJSONL,
	}
}

func testConfig() config.Config {
	cfg := config.Defaults()
	cfg.Scanner.Retries = 0
	cfg.Scanner.ConnectTimeout = 250 * time.Millisecond
	cfg.Scanner.RequestTimeout = time.Second
	cfg.Scanner.Concurrency = 2
	cfg.Scanner.RequestsPerSecond = 50
	cfg.Scanner.PerHostRate = 5
	return cfg
}

func openElasticsearchHandler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		if strings.HasSuffix(request.URL.Path, "/_security/_authenticate") {
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"error":"security_exception"}`)
			return
		}
		writer.WriteHeader(http.StatusOK)
		if request.URL.Path == "/" || request.URL.Path == "" {
			_, _ = io.WriteString(writer, elasticsearchRootBody)
			return
		}
		_, _ = io.WriteString(writer, `{"status":"green"}`)
	}
}

func findingCheckIDs(t *testing.T, payload []byte) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	for {
		var finding model.Finding
		if err := decoder.Decode(&finding); err != nil {
			if errors.Is(err, io.EOF) {
				return ids
			}
			t.Fatalf("Decode() error = %v payload = %s", err, payload)
		}
		ids[finding.CheckID] = true
	}
}

func assertGetOnlyAllowlisted(t *testing.T, requests []recordedRequest) {
	t.Helper()
	allowed := map[string]struct{}{"/": {}}
	for _, name := range []capability.Name{
		capability.NameHealth,
		capability.NameState,
		capability.NameNodes,
		capability.NameCat,
		capability.NameIndices,
		capability.NameSecurity,
	} {
		method, path, ok := capability.ReadOnlyProbe(name)
		if !ok || method != http.MethodGet {
			t.Fatalf("ReadOnlyProbe(%s) = %s %s ok=%t", name, method, path, ok)
		}
		allowed[path] = struct{}{}
	}
	if len(requests) == 0 {
		t.Fatal("no HTTP requests recorded")
	}
	for _, request := range requests {
		if request.Method != http.MethodGet {
			t.Errorf("method = %q, want GET path=%q", request.Method, request.Path)
		}
		if request.Query != "" {
			t.Errorf("query = %q, want empty", request.Query)
		}
		path := request.Path
		if path == "" {
			path = "/"
		}
		if _, ok := allowed[path]; !ok {
			t.Errorf("path %q is not allowlisted", request.Path)
		}
	}
}

func clearProxyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("NO_PROXY", "*")
}

type recordedRequest struct {
	Method string
	Path   string
	Query  string
}

type methodRecorder struct {
	mu       sync.Mutex
	requests []recordedRequest
}

func newMethodRecorder() *methodRecorder {
	return &methodRecorder{}
}

func (recorder *methodRecorder) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.mu.Lock()
		recorder.requests = append(recorder.requests, recordedRequest{
			Method: request.Method,
			Path:   request.URL.Path,
			Query:  request.URL.RawQuery,
		})
		recorder.mu.Unlock()
		next.ServeHTTP(writer, request)
	})
}

func (recorder *methodRecorder) snapshot() []recordedRequest {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	cloned := make([]recordedRequest, len(recorder.requests))
	copy(cloned, recorder.requests)
	return cloned
}

func TestScanLoadsOptionalSignatures(t *testing.T) {
	clearProxyEnv(t)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		writer.WriteHeader(http.StatusOK)
		body := strings.Replace(elasticsearchRootBody, "8.19.19", "9.4.4", 1)
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

	t.Chdir(t.TempDir())
	var stdout bytes.Buffer
	options := testScanOptions(t, server.URL, &stdout)
	options.SignatureDir = dir
	result, err := Scan(context.Background(), options)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Findings == 0 {
		t.Fatal("expected signature findings")
	}
	ids := findingCheckIDs(t, stdout.Bytes())
	if !ids["garga.vuln.example-version-only-94"] {
		t.Fatalf("missing signature finding: %v", ids)
	}
}
