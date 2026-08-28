package secrets

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/credential"
)

func TestEngineFindsMaskedSecretsAndRejectsWrites(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	methods := map[string]string{}
	bodies := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		methods[request.URL.Path] = request.Method
		if request.Body != nil && request.Body != http.NoBody {
			payload, _ := io.ReadAll(request.Body)
			if len(payload) > 0 {
				bodies++
			}
		}
		mu.Unlock()
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/":
			writeJSON(writer, map[string]any{"cluster_name": "garga-test", "version": map[string]any{"number": "8.19.0"}})
		case request.Method == http.MethodGet && request.URL.Path == "/_security/_authenticate":
			writeJSON(writer, map[string]any{"username": "garga-test"})
		case request.Method == http.MethodGet && request.URL.Path == "/_cat/indices":
			writeJSON(writer, []map[string]string{{"index": "app-logs", "status": "open"}, {"index": ".security-7", "status": "open"}})
		case request.Method == http.MethodGet && request.URL.Path == "/_alias":
			writeJSON(writer, map[string]any{})
		case request.Method == http.MethodGet && request.URL.Path == "/_data_stream":
			writeJSON(writer, map[string]any{"data_streams": []any{}})
		case request.Method == http.MethodGet && request.URL.Path == "/app-logs/_mapping":
			writeJSON(writer, mappingFixture())
		case request.Method == http.MethodPost && request.URL.Path == "/app-logs/_search":
			writeJSON(writer, searchFixture())
		default:
			if request.Method != http.MethodGet && request.Method != http.MethodPost {
				t.Errorf("unexpected method %s %s", request.Method, request.URL.Path)
			}
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	engine, err := NewEngine(Options{RateLimit: 100, Concurrency: 1, SampleSize: 10, MaxDocuments: 50, Timeout: time.Minute, AllowPlaintextAuth: true}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.ReachableTargets != 1 {
		t.Fatalf("reachable = %d", result.Summary.ReachableTargets)
	}
	if result.Summary.ScanMode != ScanModeNormal {
		t.Fatalf("scan_mode = %s", result.Summary.ScanMode)
	}
	var sawPassword, sawSecurity, leaked bool
	for _, finding := range result.Findings {
		if finding.Category == "credential.password" {
			sawPassword = true
			if finding.MaskedPreview == "fake-password-garga-test-ONLY" {
				leaked = true
			}
			if finding.Secret != "fake-password-garga-test-ONLY" {
				t.Fatalf("PDF secret missing: %#v", finding)
			}
		}
		if finding.Category == "exposure.security_index" {
			sawSecurity = true
			if finding.Secret != "" {
				t.Fatal("security index finding dumped material")
			}
		}
	}
	if !sawPassword || !sawSecurity || leaked {
		t.Fatalf("findings incomplete password=%t security=%t leaked=%t count=%d", sawPassword, sawSecurity, leaked, len(result.Findings))
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "fake-password-garga-test-ONLY") {
		t.Fatal("JSON encoding leaked the full password")
	}
	mu.Lock()
	defer mu.Unlock()
	if methods["/app-logs/_search"] != http.MethodPost {
		t.Fatalf("search method = %q", methods["/app-logs/_search"])
	}
	for path, method := range methods {
		switch method {
		case http.MethodGet, http.MethodPost:
		default:
			t.Fatalf("non-read-only method %s %s", method, path)
		}
		if method == http.MethodPost && !strings.HasSuffix(path, "/_search") {
			t.Fatalf("POST used for %s", path)
		}
	}
}

func TestEngineRateLimitAnd429DoNotCrash(t *testing.T) {
	t.Parallel()
	var searches int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			writeJSON(writer, map[string]any{"cluster_name": "retry", "version": map[string]any{"number": "8.19.0"}})
		case "/_security/_authenticate":
			writer.WriteHeader(http.StatusNotFound)
		case "/_cat/indices":
			writeJSON(writer, []map[string]string{{"index": "logs", "status": "open"}})
		case "/_alias", "/_data_stream":
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{}`))
		case "/logs/_mapping":
			writeJSON(writer, map[string]any{"logs": map[string]any{"mappings": map[string]any{"properties": map[string]any{"message": map[string]any{"type": "text"}}}}})
		case "/logs/_search":
			searches++
			if searches == 1 {
				writer.Header().Set("Retry-After", "0")
				writer.WriteHeader(http.StatusTooManyRequests)
				return
			}
			writeJSON(writer, map[string]any{"hits": map[string]any{"hits": []any{}}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	engine, err := NewEngine(Options{RateLimit: 50, Retries: 2, SampleSize: 5, AllowPlaintextAuth: true, Timeout: 15 * time.Second}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Targets[0].Reachable {
		t.Fatalf("target error = %s", result.Targets[0].Error)
	}
}

func TestEngineDeepScanIncludesGenericSourceFields(t *testing.T) {
	t.Parallel()
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			writeJSON(writer, map[string]any{"cluster_name": "garga-test", "version": map[string]any{"number": "8.19.0"}})
		case "/_security/_authenticate":
			writeJSON(writer, map[string]any{"username": "garga-test"})
		case "/_cat/indices":
			writeJSON(writer, []map[string]string{{"index": "app-logs", "status": "open"}})
		case "/_alias", "/_data_stream":
			writeJSON(writer, map[string]any{})
		case "/app-logs/_mapping":
			writeJSON(writer, map[string]any{"app-logs": map[string]any{"mappings": map[string]any{"properties": map[string]any{
				"password": map[string]any{"type": "keyword"},
				"sku":      map[string]any{"type": "keyword"},
			}}}})
		case "/app-logs/_search":
			payload, _ := io.ReadAll(request.Body)
			bodies = append(bodies, string(payload))
			writeJSON(writer, map[string]any{"hits": map[string]any{"hits": []any{}}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	normal, err := NewEngine(Options{RateLimit: 100, SampleSize: 5, AllowPlaintextAuth: true, Timeout: time.Minute}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normal.Scan(context.Background(), []string{server.URL}); err != nil {
		t.Fatal(err)
	}
	if len(bodies) == 0 {
		t.Fatal("normal scan sent no search")
	}
	if strings.Contains(bodies[0], "sku") {
		t.Fatalf("normal _source included sku: %s", bodies[0])
	}

	bodies = nil
	deepOpts := Options{RateLimit: 100, SampleSize: 5, AllowPlaintextAuth: true, Timeout: time.Minute}
	ApplyProfile(&deepOpts, DeepScanProfile(), ProfileOverrides{SampleSize: true})
	deep, err := NewEngine(deepOpts, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := deep.Scan(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.ScanMode != ScanModeDeep {
		t.Fatalf("scan_mode = %s", result.Summary.ScanMode)
	}
	if len(bodies) == 0 || !strings.Contains(bodies[0], "sku") {
		t.Fatalf("deep _source missing sku: %v", bodies)
	}
}

func TestEngineRequiresAllowPlaintextAuth(t *testing.T) {
	t.Parallel()
	secret, err := credential.NewBasic("garga", []byte("fake-password-garga-test-ONLY"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	engine, err := NewEngine(Options{RateLimit: 10, Timeout: time.Second}, secret, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), []string{"http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Targets[0].Reachable || !strings.Contains(result.Targets[0].Error, "HTTP") {
		t.Fatalf("expected plaintext auth refusal, got %#v", result.Targets[0])
	}
}

func TestClientRejectsNonAllowlistedMethods(t *testing.T) {
	t.Parallel()
	if allowlistedRequest(http.MethodDelete, "/app/_doc/1") {
		t.Fatal("DELETE must not be allowlisted")
	}
	if allowlistedRequest(http.MethodPut, "/app/_mapping") {
		t.Fatal("PUT mapping must not be allowlisted")
	}
	if allowlistedRequest(http.MethodPost, "/_bulk") {
		t.Fatal("POST bulk must not be allowlisted")
	}
	if !allowlistedRequest(http.MethodPost, "/app/_search") {
		t.Fatal("POST _search must be allowlisted")
	}
}

func TestSearchBodyUsesDocSort(t *testing.T) {
	t.Parallel()
	raw, err := searchBody(10, []string{"password"}, []any{0})
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	sort, _ := body["sort"].([]any)
	if len(sort) != 1 || sort[0] != "_doc" {
		t.Fatalf("sort = %#v, want [_doc]", body["sort"])
	}
	if _, ok := body["search_after"]; !ok {
		t.Fatal("search_after missing")
	}
	source, _ := body["_source"].([]any)
	if len(source) != 1 || source[0] != "password" {
		t.Fatalf("_source = %#v", body["_source"])
	}
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}

func mappingFixture() map[string]any {
	properties := map[string]any{
		"password": map[string]any{"type": "keyword"},
		"message":  map[string]any{"type": "text"},
	}
	mappings := map[string]any{"properties": properties}
	return map[string]any{"app-logs": map[string]any{"mappings": mappings}}
}

func searchFixture() map[string]any {
	hit := map[string]any{
		"_id":     "1",
		"_source": map[string]any{"password": "fake-password-garga-test-ONLY"},
		"sort":    []any{"1"},
	}
	return map[string]any{"hits": map[string]any{"hits": []any{hit}}}
}
