package collector

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/target"
	"github.com/cumakurt/garga/internal/transport"
)

func TestCollectUsesGETOnlyRetriesTransientFailureAndSkipsDeepPlan(t *testing.T) {
	var mu sync.Mutex
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests[request.URL.Path]++
		count := requests[request.URL.Path]
		mu.Unlock()
		if request.Method != http.MethodGet || request.Body != nil && request.Body != http.NoBody || request.ContentLength > 0 {
			t.Errorf("unsafe request: method=%s body=%v length=%d", request.Method, request.Body, request.ContentLength)
		}
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/_cluster/health" && count == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(writer, `{"error":"transient"}`)
			return
		}
		status, response := fixtureResponse(request.URL.Path)
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, response)
	}))
	defer server.Close()

	parsed, err := target.Parse(server.URL, "test")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := target.Endpoint(parsed)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	transportOptions, err := transport.OptionsFromConfig(cfg, "garga/test")
	if err != nil {
		t.Fatal(err)
	}
	transportOptions.DisableEnvironmentProxy = true
	transportOptions.MaxResponseBytes = cfg.Health.MaxResponseBytes
	factory, err := transport.NewFactory(transportOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer factory.CloseIdleConnections()

	dataCollector, err := New(Options{Endpoint: endpoint, Client: factory.Client(), Concurrency: 4, Rate: 100, Retries: 1})
	if err != nil {
		t.Fatal(err)
	}
	result, err := dataCollector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Retried != 1 || result.Requests == 0 || result.Bytes == 0 {
		t.Fatalf("telemetry = requests %d bytes %d retried %d", result.Requests, result.Bytes, result.Retried)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests["/_cluster/health"] != 2 {
		t.Fatalf("cluster health requests = %d, want 2", requests["/_cluster/health"])
	}
	for path := range requests {
		if path == "/_ilm/explain" || path == "/_tasks" || path == "/_data_stream" || path == "/_snapshot/_all" || path == "/_nodes/settings" {
			t.Fatalf("normal collection called deep path %q", path)
		}
	}
}

func TestCollectClassifiesAuthenticationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	parsed, _ := target.Parse(server.URL, "test")
	endpoint, _ := target.Endpoint(parsed)
	transportOptions, _ := transport.OptionsFromConfig(config.Defaults(), "garga/test")
	transportOptions.DisableEnvironmentProxy = true
	factory, err := transport.NewFactory(transportOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer factory.CloseIdleConnections()
	dataCollector, err := New(Options{Endpoint: endpoint, Client: factory.Client(), Concurrency: 1, Rate: 100})
	if err != nil {
		t.Fatal(err)
	}
	_, err = dataCollector.Collect(context.Background())
	var collectorError *Error
	if !errors.As(err, &collectorError) || collectorError.Kind != ErrorAuthentication {
		t.Fatalf("Collect() error = %#v", err)
	}
}

func TestCollectRejectsUnsupportedProductVersions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{name: "elasticsearch 7.16", body: `{"cluster_name":"fixture","cluster_uuid":"uuid","version":{"number":"7.16.3"},"tagline":"You Know, for Search"}`},
		{name: "opensearch", body: `{"cluster_name":"fixture","cluster_uuid":"uuid","version":{"number":"2.11.0","distribution":"opensearch"},"tagline":"The OpenSearch Project: https://opensearch.org/"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/" {
					t.Errorf("unexpected path %s", request.URL.Path)
				}
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, test.body)
			}))
			t.Cleanup(server.Close)
			dataCollector := newTestCollector(t, server.URL, Options{Concurrency: 1, Rate: 100})
			_, err := dataCollector.Collect(context.Background())
			var collectorError *Error
			if !errors.As(err, &collectorError) || collectorError.Kind != ErrorProduct {
				t.Fatalf("Collect() error = %#v, want product error", err)
			}
		})
	}
}

func TestCollectDeepSnapshotHistoryUsesBoundedQuery(t *testing.T) {
	t.Parallel()
	var snapshotQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/_snapshot/_all":
			_, _ = io.WriteString(writer, `{"fs-repo":{"type":"fs"}}`)
		case "/_snapshot/fs-repo/_all":
			snapshotQuery = request.URL.Query()
			_, _ = io.WriteString(writer, `{"snapshots":[]}`)
		default:
			status, response := fixtureResponse(request.URL.Path)
			writer.WriteHeader(status)
			_, _ = io.WriteString(writer, response)
		}
	}))
	defer server.Close()
	dataCollector := newTestCollector(t, server.URL, Options{Concurrency: 2, Rate: 100, Deep: true})
	if _, err := dataCollector.Collect(context.Background()); err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if snapshotQuery.Get("size") != "20" || snapshotQuery.Get("order") != "desc" || snapshotQuery.Get("sort") != "start_time" {
		t.Fatalf("snapshot query = %v, want size=20 order=desc sort=start_time", snapshotQuery)
	}
}

func TestCollectRecordsCanceledCollectors(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/" {
			select {
			case <-started:
			default:
				close(started)
			}
			<-request.Context().Done()
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"cluster_name":"fixture","cluster_uuid":"uuid","version":{"number":"8.19.19"},"tagline":"You Know, for Search"}`)
	}))
	defer server.Close()
	dataCollector := newTestCollector(t, server.URL, Options{Concurrency: 1, Rate: 100})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	var result ResponseSet
	go func() {
		var err error
		result, err = dataCollector.Collect(ctx)
		errCh <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a non-root collector request")
	}
	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Collect() error = %v, want context.Canceled", err)
	}
	canceled := 0
	for _, collector := range result.Collectors {
		if collector.Status == "skipped" && collector.Reason == "canceled" {
			canceled++
		}
	}
	if canceled == 0 {
		t.Fatalf("collectors = %#v, want canceled leftovers", result.Collectors)
	}
}

func newTestCollector(t *testing.T, rawURL string, options Options) *Collector {
	t.Helper()
	parsed, err := target.Parse(rawURL, "test")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := target.Endpoint(parsed)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	transportOptions, err := transport.OptionsFromConfig(cfg, "garga/test")
	if err != nil {
		t.Fatal(err)
	}
	transportOptions.DisableEnvironmentProxy = true
	transportOptions.MaxResponseBytes = cfg.Health.MaxResponseBytes
	factory, err := transport.NewFactory(transportOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(factory.CloseIdleConnections)
	options.Endpoint = endpoint
	options.Client = factory.Client()
	if options.Concurrency == 0 {
		options.Concurrency = 1
	}
	if options.Rate == 0 {
		options.Rate = 100
	}
	dataCollector, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return dataCollector
}

func fixtureResponse(path string) (int, string) {
	switch path {
	case "/":
		return http.StatusOK, `{"cluster_name":"fixture","cluster_uuid":"uuid","version":{"number":"8.19.19"},"tagline":"You Know, for Search"}`
	case "/_cluster/health":
		return http.StatusOK, `{"status":"green","unassigned_shards":0}`
	case "/_security/_authenticate":
		return http.StatusUnauthorized, `{"error":"authentication required"}`
	case "/_cat/indices", "/_cat/shards":
		return http.StatusOK, `[]`
	default:
		return http.StatusOK, `{}`
	}
}
