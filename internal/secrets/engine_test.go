package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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
		case request.Method == http.MethodPost && request.URL.Path == "/.security-7/_search":
			writeJSON(writer, map[string]any{"hits": map[string]any{"hits": []any{}}})
		default:
			if request.Method != http.MethodGet && request.Method != http.MethodPost {
				t.Errorf("unexpected method %s %s", request.Method, request.URL.Path)
			}
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	engine, err := NewEngine(Options{RateLimit: 100, Concurrency: 1, SampleSize: 10, MaxDocuments: 50, Timeout: time.Minute, AllowPlaintextAuth: true, IncludeSystemIndices: true}, nil, "garga/test", nil)
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
			if finding.MaskedPreview == plaintextCanary {
				leaked = true
			}
			if finding.ID == "" || finding.Title == "" || finding.Remediation == "" {
				t.Fatalf("canonical metadata missing: %#v", finding)
			}
		}
		if finding.Category == "exposure.security_index" {
			sawSecurity = true
		}
	}
	if !sawPassword || !sawSecurity || leaked {
		t.Fatalf("findings incomplete password=%t security=%t leaked=%t count=%d", sawPassword, sawSecurity, leaked, len(result.Findings))
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), plaintextCanary) {
		t.Fatal("JSON encoding leaked the full password")
	}
	if strings.Contains(fmt.Sprintf("%#v", result), plaintextCanary) {
		t.Fatal("canonical result retained the full password")
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

	assertEngineRenderersStayMaskedAndParity(t, result)
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

func TestEngineRejectsGenericHTTPServiceAsElasticsearch(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/_cat/indices":
			writeJSON(writer, []any{})
		default:
			writeJSON(writer, map[string]any{"service": "generic-http"})
		}
	}))
	defer server.Close()
	engine, err := NewEngine(Options{RateLimit: 100, Timeout: time.Minute}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Targets) != 1 || !result.Targets[0].Reachable {
		t.Fatalf("target reachability = %#v", result.Targets)
	}
	if !strings.Contains(result.Targets[0].Error, "not a confirmed Elasticsearch endpoint") {
		t.Fatalf("target error = %q", result.Targets[0].Error)
	}
	if result.Summary.PartialFailures != 1 || len(result.Findings) != 0 {
		t.Fatalf("generic service was scanned as Elasticsearch: %#v", result)
	}
}

func TestEngineCountsHTTPAuthenticationResponsesAsReachable(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(status)
			}))
			defer server.Close()
			engine, err := NewEngine(Options{RateLimit: 100, Timeout: time.Minute}, nil, "garga/test", nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := engine.Scan(context.Background(), []string{server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if !result.Targets[0].Reachable || result.Summary.ReachableTargets != 1 {
				t.Fatalf("HTTP %d target was reported unreachable: %#v", status, result)
			}
			expected := fmt.Sprintf("HTTP %d %s", status, http.StatusText(status))
			if !strings.Contains(result.Targets[0].Error, expected) {
				t.Fatalf("target error = %q, want %q", result.Targets[0].Error, expected)
			}
		})
	}
}

func TestEngineReportsMalformedRootAsReachableProtocolFailure(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"cluster_name":`))
	}))
	defer server.Close()
	engine, err := NewEngine(Options{RateLimit: 100, Timeout: time.Minute}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Targets[0].Reachable || result.Summary.ReachableTargets != 1 || !strings.Contains(result.Targets[0].Error, "decode /") {
		t.Fatalf("malformed HTTP response classification = %#v", result)
	}
}

func TestEngineReportsPartialShardFailure(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			writeJSON(writer, map[string]any{"cluster_name": "partial", "version": map[string]any{"number": "9.1.0"}})
		case "/_security/_authenticate":
			writer.WriteHeader(http.StatusForbidden)
		case "/_cat/indices":
			writeJSON(writer, []map[string]string{{"index": "logs", "status": "open"}})
		case "/_alias", "/_data_stream":
			writeJSON(writer, map[string]any{})
		case "/logs/_mapping":
			writeJSON(writer, map[string]any{"logs": map[string]any{"mappings": map[string]any{"properties": map[string]any{"password": map[string]any{"type": "keyword"}}}}})
		case "/logs/_search":
			writeJSON(writer, map[string]any{
				"_shards": map[string]any{"total": 2, "successful": 1, "failed": 1},
				"hits":    map[string]any{"hits": []any{}},
			})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	engine, err := NewEngine(Options{RateLimit: 100, Timeout: time.Minute}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.PartialFailures != 1 || len(result.Targets) != 1 {
		t.Fatalf("partial failure summary = %#v", result.Summary)
	}
	if !strings.Contains(result.Targets[0].Error, "failed shards") {
		t.Fatalf("target error = %q", result.Targets[0].Error)
	}
	if result.Summary.IndicesInspected != 0 || result.Summary.DocumentsExamined != 0 {
		t.Fatalf("partial shard response counted as examined: %#v", result.Summary)
	}
}

func TestNormalScanDoesNotDownloadFullSourceWithoutSelectedMappingFields(t *testing.T) {
	t.Parallel()
	var searches atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/":
			writeJSON(writer, map[string]any{"cluster_name": "bounded", "version": map[string]any{"number": "9.1.0"}})
		case "/_security/_authenticate":
			writer.WriteHeader(http.StatusForbidden)
		case "/_cat/indices":
			writeJSON(writer, []map[string]string{{"index": "metrics", "status": "open"}})
		case "/_alias", "/_data_stream":
			writeJSON(writer, map[string]any{})
		case "/metrics/_mapping":
			writeJSON(writer, map[string]any{"metrics": map[string]any{"mappings": map[string]any{"properties": map[string]any{
				"temperature": map[string]any{"type": "double"},
			}}}})
		case "/metrics/_search":
			searches.Add(1)
			writeJSON(writer, map[string]any{"hits": map[string]any{"hits": []any{}}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	engine, err := NewEngine(Options{RateLimit: 100, Timeout: time.Minute}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if searches.Load() != 0 || result.Summary.DocumentsExamined != 0 || result.Summary.IndicesInspected != 1 {
		t.Fatalf("normal mapping-first bounds failed: searches=%d summary=%#v", searches.Load(), result.Summary)
	}
}

func TestSecurityIndexFindingRequiresIncludedAndSuccessfulReadProbe(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		includeSystem bool
		probeStatus   int
		wantProbes    int64
	}{
		{name: "excluded by default", probeStatus: http.StatusOK},
		{name: "included but denied", includeSystem: true, probeStatus: http.StatusForbidden, wantProbes: 1},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var probes atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/":
					writeJSON(writer, map[string]any{"cluster_name": "security-probe", "version": map[string]any{"number": "9.1.0"}})
				case "/_security/_authenticate":
					writer.WriteHeader(http.StatusForbidden)
				case "/_cat/indices":
					writeJSON(writer, []map[string]string{{"index": ".security-7", "status": "open"}})
				case "/_alias", "/_data_stream":
					writeJSON(writer, map[string]any{})
				case "/.security-7/_search":
					probes.Add(1)
					writer.WriteHeader(test.probeStatus)
					if test.probeStatus == http.StatusOK {
						_, _ = writer.Write([]byte(`{"hits":{"hits":[]}}`))
					}
				default:
					writer.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			engine, err := NewEngine(Options{RateLimit: 100, Retries: 0, Timeout: time.Minute, IncludeSystemIndices: test.includeSystem}, nil, "garga/test", nil)
			if err != nil {
				t.Fatal(err)
			}
			result, err := engine.Scan(context.Background(), []string{server.URL})
			if err != nil {
				t.Fatal(err)
			}
			if probes.Load() != test.wantProbes || len(result.Findings) != 0 || result.Summary.IndicesInspected != 0 {
				t.Fatalf("security probe classification: probes=%d report=%#v", probes.Load(), result)
			}
		})
	}
}

func TestCatalogExpansionHandlesExplicitAliasesAndVisibleDataStreams(t *testing.T) {
	t.Parallel()
	engine, err := NewEngine(Options{Indices: []string{"logs-alias", "events-*"}}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := engine.expandCatalogIndices(
		[]string{"logs-000001", ".ds-events-prod-2026.08.28-000001", "unrelated"},
		map[string][]string{"logs-alias": {"logs-000001"}},
		map[string]dataStreamIndices{
			"events-prod":   {backing: []string{".ds-events-prod-2026.08.28-000001"}},
			"hidden-events": {backing: []string{".ds-hidden-events-000001"}, hidden: true},
		},
	)
	want := []string{".ds-events-prod-2026.08.28-000001", "logs-000001"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("expanded indices = %v, want %v", got, want)
	}
}

func TestEngineHandlesOneHundredIndicesWithinConfiguredBounds(t *testing.T) {
	t.Parallel()
	const indexCount = 101
	rows := make([]map[string]string, indexCount)
	for index := range rows {
		rows[index] = map[string]string{"index": fmt.Sprintf("logs-%03d", index), "status": "open"}
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		switch {
		case request.URL.Path == "/":
			writeJSON(writer, map[string]any{"cluster_name": "large", "version": map[string]any{"number": "9.1.0"}})
		case request.URL.Path == "/_security/_authenticate":
			writer.WriteHeader(http.StatusForbidden)
		case request.URL.Path == "/_cat/indices":
			writeJSON(writer, rows)
		case request.URL.Path == "/_alias" || request.URL.Path == "/_data_stream":
			writeJSON(writer, map[string]any{})
		case strings.HasSuffix(request.URL.Path, "/_mapping"):
			indexName := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/"), "/_mapping")
			writeJSON(writer, map[string]any{indexName: map[string]any{"mappings": map[string]any{"properties": map[string]any{"password": map[string]any{"type": "keyword"}}}}})
		case strings.HasSuffix(request.URL.Path, "/_search"):
			writeJSON(writer, map[string]any{"hits": map[string]any{"hits": []any{map[string]any{
				"_id": "1", "_source": map[string]any{"password": plaintextCanary}, "sort": []any{},
			}}}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	engine, err := NewEngine(Options{
		RateLimit: 100, Timeout: time.Minute, SampleSize: 1, MaxDocuments: indexCount,
		MaxDepth: 8, MaxArrayItems: 8, MaxObjectSize: 32, MaxFieldBytes: 1024,
	}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.IndicesInspected != indexCount || result.Summary.DocumentsExamined != indexCount {
		t.Fatalf("large scan counters = %#v", result.Summary)
	}
	if result.Summary.Findings != indexCount || result.Summary.Occurrences != indexCount || result.Summary.FindingsTruncated {
		t.Fatalf("large scan findings = %#v", result.Summary)
	}
	if got, maximum := requests.Load(), int64(5+2*indexCount); got > maximum {
		t.Fatalf("requests = %d, want at most %d", got, maximum)
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

func TestEngineReturnsContextCancellationAfterWorkersStop(t *testing.T) {
	t.Parallel()
	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		<-request.Context().Done()
	}))
	defer server.Close()

	engine, err := NewEngine(Options{RateLimit: 100, Timeout: time.Minute}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-requestStarted
		cancel()
	}()
	if _, err := engine.Scan(ctx, []string{server.URL}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan error = %v, want context cancellation", err)
	}
}

func TestMergeFindingKeepsTargetsAndDistinctSecretsSeparate(t *testing.T) {
	t.Parallel()
	engine, err := NewEngine(Options{}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	dedup := map[string]*Finding{}
	base := Finding{
		Target: "https://one.example:9200", Cluster: "one", Index: "logs", FieldPath: "password",
		Category: "credential.password", Detector: "sensitive-field", Severity: SeverityCritical,
		Confidence: ConfidenceHigh, MaskedPreview: "GARGA_...91A2", Occurrences: 1,
		dedupFingerprint: "first-keyed-digest",
	}
	engine.mergeFinding(dedup, base)
	otherTarget := base
	otherTarget.Target = "https://two.example:9200"
	otherTarget.Cluster = "two"
	engine.mergeFinding(dedup, otherTarget)
	otherSecret := base
	otherSecret.dedupFingerprint = "second-keyed-digest"
	engine.mergeFinding(dedup, otherSecret)
	engine.mergeFinding(dedup, base)
	if len(dedup) != 3 {
		t.Fatalf("deduplicated findings = %d, want separate target and secret entries", len(dedup))
	}
	var merged bool
	for _, finding := range dedup {
		if finding.Target == base.Target && finding.Occurrences == 2 {
			merged = true
		}
		if finding.dedupFingerprint != "" {
			t.Fatal("stored canonical finding retained the ephemeral fingerprint")
		}
	}
	if !merged {
		t.Fatal("repeated occurrence on the same target was not merged")
	}
}

func TestMergeFindingBoundsCanonicalReportSize(t *testing.T) {
	t.Parallel()
	engine, err := NewEngine(Options{MinConfidence: ConfidenceLow}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	dedup := make(map[string]*Finding, MaxReportFindings)
	var dropped bool
	for index := 0; index <= MaxReportFindings; index++ {
		finding := Finding{
			Target: "https://one.example:9200", Cluster: "one", Index: "logs",
			FieldPath: fmt.Sprintf("password_%d", index), Category: "credential.password",
			Detector: "sensitive-field", Severity: SeverityCritical, Confidence: ConfidenceHigh,
			MaskedPreview: "s********t", Occurrences: 1,
			dedupFingerprint: fmt.Sprintf("digest-%d", index),
		}
		if engine.mergeFinding(dedup, finding) {
			dropped = true
		}
	}
	if !dropped || len(dedup) != MaxReportFindings {
		t.Fatalf("dedup size = %d dropped=%t, want bounded report", len(dedup), dropped)
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

func assertEngineRenderersStayMaskedAndParity(t *testing.T, result ScanReport) {
	t.Helper()
	assertNoPlaintextCanary(t, "canonical", []byte(fmt.Sprintf("%#v", result)))
	canonical := parityFromSummary(result.Summary)

	var jsonBuffer, table, sarif, pdf bytes.Buffer
	if err := WriteReport(&jsonBuffer, FormatJSON, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteReport(&table, FormatTable, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteReport(&sarif, FormatSARIF, result); err != nil {
		t.Fatal(err)
	}
	if err := WritePDF(&pdf, result); err != nil {
		t.Fatal(err)
	}
	assertNoPlaintextCanary(t, "JSON", jsonBuffer.Bytes())
	assertNoPlaintextCanary(t, "table", table.Bytes())
	assertNoPlaintextCanary(t, "SARIF", sarif.Bytes())
	assertNoPlaintextCanary(t, "PDF", pdf.Bytes())

	var decoded ScanReport
	if err := json.Unmarshal(jsonBuffer.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	assertParityEqual(t, "JSON", canonical, parityFromSummary(decoded.Summary))
	assertParityEqual(t, "table", canonical, parseTableParity(t, table.String()))
	assertParityCounters(t, "PDF", canonical, parsePDFParity(t, pdf.Bytes()))

	if extracted, ok := extractedPDFText(t, pdf.Bytes()); ok {
		assertNoPlaintextCanary(t, "PDF text", []byte(extracted))
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
		"_source": map[string]any{"password": plaintextCanary},
		"sort":    []any{"1"},
	}
	return map[string]any{"hits": map[string]any{"hits": []any{hit}}}
}

func TestSampleDocumentsCapsOversizedSearchHits(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/":
			writeJSON(writer, map[string]any{"cluster_name": "oversize", "version": map[string]any{"number": "8.19.0"}})
		case request.Method == http.MethodGet && request.URL.Path == "/_security/_authenticate":
			writer.WriteHeader(http.StatusNotFound)
		case request.Method == http.MethodGet && request.URL.Path == "/_cat/indices":
			writeJSON(writer, []map[string]string{{"index": "app-logs", "status": "open"}})
		case request.Method == http.MethodGet && (request.URL.Path == "/_alias" || request.URL.Path == "/_data_stream"):
			writeJSON(writer, map[string]any{})
		case request.Method == http.MethodGet && request.URL.Path == "/app-logs/_mapping":
			writeJSON(writer, mappingFixture())
		case request.Method == http.MethodPost && request.URL.Path == "/app-logs/_search":
			hits := make([]any, 0, 50)
			for index := 0; index < 50; index++ {
				hits = append(hits, map[string]any{
					"_id":     fmt.Sprintf("%d", index),
					"_source": map[string]any{"password": "fake-password-garga-test-ONLY"},
					"sort":    []any{index},
				})
			}
			writeJSON(writer, map[string]any{"hits": map[string]any{"hits": hits}})
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	engine, err := NewEngine(Options{
		RateLimit: 100, Concurrency: 1, SampleSize: 2, MaxDocuments: 2,
		Timeout: time.Minute, AllowPlaintextAuth: true, SearchBatch: 2,
	}, nil, "garga/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := engine.Scan(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.DocumentsExamined != 2 {
		t.Fatalf("documents examined = %d, want sample cap 2 (malicious search returned 50 hits)", result.Summary.DocumentsExamined)
	}
}
