package capability

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/fingerprint"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/probe"
	"github.com/cumakurt/garga/internal/transport"
)

const canary = "credential-canary"

func TestDiscoverConfirmedOpenCluster(t *testing.T) {
	t.Parallel()

	recorder := newRequestRecorder()
	server := httptest.NewServer(recorder.handler(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, `{"cluster_name":"`+canary+`","status":"green"}`)
	}))
	defer server.Close()

	result, err := discover(t, newTestDetector(t), endpointForServer(t, server.URL), confirmedIdentity(), openRoot())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	assertAvailability(t, result, map[Name]Availability{
		NameRoot:      AvailabilityAvailable,
		NameHealth:    AvailabilityAvailable,
		NameState:     AvailabilityAvailable,
		NameNodes:     AvailabilityAvailable,
		NameCat:       AvailabilityAvailable,
		NameIndices:   AvailabilityAvailable,
		NameSecurity:  AvailabilityAvailable,
		NameAnonymous: AvailabilityAvailable,
		NameBasicAuth: AvailabilityUnknown,
		NameAPIKey:    AvailabilityUnknown,
	})
	if result.Version != "9.4.4" || !result.IsAvailable(NameAnonymous) || result.Suppresses(NameHealth) {
		t.Fatalf("Discover() = %#v", result)
	}
	assertSafeRequests(t, recorder.snapshot(), "")
	assertNoCanary(t, result)
}

func TestDiscoverUnsupportedAPISuppressesDependentChecks(t *testing.T) {
	t.Parallel()

	recorder := newRequestRecorder()
	server := httptest.NewServer(recorder.handler(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(request.URL.Path, pathNodes):
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"error":"`+canary+`"}`)
		case strings.HasSuffix(request.URL.Path, pathSecurity):
			writer.WriteHeader(http.StatusNotImplemented)
		default:
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, `{"ok":true}`)
		}
	}))
	defer server.Close()

	result, err := discover(t, newTestDetector(t), endpointForServer(t, server.URL), confirmedIdentity(), openRoot())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if !result.Suppresses(NameNodes) || !result.Suppresses(NameSecurity) {
		t.Fatalf("missing APIs were not suppressed: %#v", result)
	}
	if result.Suppresses(NameHealth) || !result.Exists(NameHealth) || result.Exists(NameNodes) {
		t.Fatalf("supported APIs were misclassified: %#v", result)
	}
	assertSafeRequests(t, recorder.snapshot(), "")
	assertNoCanary(t, result)
}

func TestDiscoverAuthRequiredDoesNotSuppressAPIPresence(t *testing.T) {
	t.Parallel()

	challenge := []probe.HeaderField{
		{Name: "Content-Type", Values: []string{"application/json"}},
		{Name: "Www-Authenticate", Values: []string{`Basic realm="security" charset="UTF-8"`, "ApiKey"}},
		{Name: "X-Elastic-Product", Values: []string{"Elasticsearch"}},
	}
	recorder := newRequestRecorder()
	server := httptest.NewServer(recorder.handler(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Www-Authenticate", `Basic realm="security" charset="UTF-8"`)
		writer.Header().Add("Www-Authenticate", "ApiKey")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, `{"error":"`+canary+`"}`)
	}))
	defer server.Close()

	root := probe.Result{StatusCode: http.StatusUnauthorized, Headers: challenge}
	result, err := discover(t, newTestDetector(t), endpointForServer(t, server.URL), confirmedIdentity(), root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	for _, name := range []Name{NameRoot, NameHealth, NameState, NameNodes, NameCat, NameSecurity} {
		if result.Suppresses(name) || !result.Exists(name) || result.IsAvailable(name) {
			t.Fatalf("%s = %q, want auth-required existence", name, result.AvailabilityOf(name))
		}
	}
	if result.IsAvailable(NameAnonymous) || !result.IsAvailable(NameBasicAuth) || !result.IsAvailable(NameAPIKey) {
		t.Fatalf("auth mechanisms = %#v", result)
	}
	assertSafeRequests(t, recorder.snapshot(), "")
	assertNoCanary(t, result)
}

func TestDiscoverPossibleFingerprintMakesNoRequests(t *testing.T) {
	t.Parallel()

	recorder := newRequestRecorder()
	server := httptest.NewServer(recorder.handler(func(http.ResponseWriter, *http.Request) {
		t.Error("possible fingerprint issued an HTTP request")
	}))
	defer server.Close()

	identity := fingerprint.Result{Classification: fingerprint.ClassificationPossible, Version: "8.19.19"}
	result, err := discover(t, newTestDetector(t), endpointForServer(t, server.URL), identity, openRoot())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(recorder.snapshot()) != 0 {
		t.Fatalf("requests = %#v", recorder.snapshot())
	}
	if result.Suppresses(NameHealth) || result.Version != "8.19.19" {
		t.Fatalf("ineligible result = %#v", result)
	}
	for _, capability := range result.Capabilities {
		if capability.Availability != AvailabilityUnknown || capability.Detail != "fingerprint_below_likely" {
			t.Fatalf("ineligible capability = %#v", capability)
		}
	}
}

func TestDiscoverReusesRootAndHonorsBasePath(t *testing.T) {
	t.Parallel()

	recorder := newRequestRecorder()
	server := httptest.NewServer(recorder.handler(func(writer http.ResponseWriter, request *http.Request) {
		if !strings.HasPrefix(request.URL.Path, "/elastic/") {
			t.Errorf("path = %q, want /elastic prefix", request.URL.Path)
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	endpoint := endpointForServer(t, server.URL)
	endpoint.Path = "/elastic"
	result, err := discover(t, newTestDetector(t), endpoint, confirmedIdentity(), openRoot())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if !result.IsAvailable(NameHealth) {
		t.Fatalf("Discover() = %#v", result)
	}

	requests := recorder.snapshot()
	if len(requests) != len(extraProbes) {
		t.Fatalf("request count = %d, want %d", len(requests), len(extraProbes))
	}
	for _, request := range requests {
		if request.Path == "/" || request.Path == "/elastic" || request.Path == "/elastic/" {
			t.Fatalf("root was re-probed: %#v", request)
		}
	}
	assertSafeRequests(t, requests, "/elastic")
}

func TestDiscoverActiveSafeContract(t *testing.T) {
	t.Parallel()

	recorder := newRequestRecorder()
	server := httptest.NewServer(recorder.handler(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Errorf("method = %q", request.Method)
		}
		if request.Body != nil {
			body, _ := io.ReadAll(request.Body)
			if len(body) != 0 {
				t.Errorf("body = %q", body)
			}
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := discover(t, newTestDetector(t), endpointForServer(t, server.URL), confirmedIdentity(), openRoot())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	assertSafeRequests(t, recorder.snapshot(), "")
}

func TestDiscoverAnonymousSuperuserIsRedacted(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(request.URL.Path, pathSecurity) {
			writer.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(writer, `{"username":"`+canary+`","roles":["`+canary+`","superuser"]}`)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, `{"ok":true}`)
	}))
	defer server.Close()

	result, err := discover(t, newTestDetector(t), endpointForServer(t, server.URL), confirmedIdentity(), openRoot())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if !result.AnonymousSuperuser || !result.IsAvailable(NameSecurity) {
		t.Fatalf("Discover() = %#v", result)
	}
	assertNoCanary(t, result)
}

func TestDiscoverPerAPIErrorDoesNotFailDiscovery(t *testing.T) {
	t.Parallel()

	prober := stubProber{fn: func(_ context.Context, endpoint model.Endpoint) (probe.Result, error) {
		switch {
		case strings.HasSuffix(endpoint.Path, pathHealth):
			return probe.Result{}, errors.New("probe failed: HTTP error")
		case strings.HasSuffix(endpoint.Path, pathState):
			return probe.Result{StatusCode: http.StatusServiceUnavailable}, nil
		default:
			return probe.Result{StatusCode: http.StatusOK}, nil
		}
	}}
	detector, err := New(prober)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result, err := detector.Discover(context.Background(), model.Endpoint{Scheme: model.SchemeHTTP, Host: "127.0.0.1", Port: 9200}, confirmedIdentity(), openRoot())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if result.AvailabilityOf(NameHealth) != AvailabilityError || result.Suppresses(NameHealth) {
		t.Fatalf("health = %#v", capabilityByName(result, NameHealth))
	}
	if result.AvailabilityOf(NameState) != AvailabilityUnknown || result.Suppresses(NameState) {
		t.Fatalf("state = %#v", capabilityByName(result, NameState))
	}
	if !result.IsAvailable(NameNodes) {
		t.Fatalf("nodes should remain available: %#v", result)
	}
}

func TestDiscoverCancellationStopsRemainingProbes(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, pathHealth) {
			writer.WriteHeader(http.StatusOK)
			return
		}
		select {
		case <-started:
		default:
			close(started)
		}
		<-request.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-started
		cancel()
	}()

	result, err := newTestDetector(t).Discover(ctx, endpointForServer(t, server.URL), confirmedIdentity(), openRoot())
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("Discover() error = %v, want canceled", err)
	}
	if !result.IsAvailable(NameHealth) {
		t.Fatalf("completed health probe was lost: %#v", result)
	}
	if result.AvailabilityOf(NameSecurity) != AvailabilityUnknown {
		t.Fatalf("later probes continued after cancel: %#v", result)
	}
}

func TestDiscoverResultsAreDeterministicAndRedacted(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Warning", canary)
		writer.Header().Set("Server", canary)
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, `{"name":"`+canary+`","cluster_uuid":"`+canary+`"}`)
	}))
	defer server.Close()

	detector := newTestDetector(t)
	endpoint := endpointForServer(t, server.URL)
	first, err := discover(t, detector, endpoint, confirmedIdentity(), openRoot())
	if err != nil {
		t.Fatalf("first Discover() error = %v", err)
	}
	second, err := discover(t, detector, endpoint, confirmedIdentity(), openRoot())
	if err != nil {
		t.Fatalf("second Discover() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Discover() changed:\n%#v\n%#v", first, second)
	}
	assertNoCanary(t, first)
	if len(first.Capabilities) != len(reportOrder) {
		t.Fatalf("capabilities = %d, want %d", len(first.Capabilities), len(reportOrder))
	}
	for index, name := range reportOrder {
		if first.Capabilities[index].Name != name {
			t.Fatalf("capability[%d] = %q, want %q", index, first.Capabilities[index].Name, name)
		}
	}
}

func TestDiscoverLikelyWithoutDetectedVersionStillProbes(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	identity := fingerprint.Result{Classification: fingerprint.ClassificationLikely}
	result, err := discover(t, newTestDetector(t), endpointForServer(t, server.URL), identity, openRoot())
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if !result.IsAvailable(NameHealth) || result.Version != "" {
		t.Fatalf("Discover() = %#v", result)
	}
}

func TestNewRejectsNilInputs(t *testing.T) {
	t.Parallel()

	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) returned nil error")
	}
	var detector *Detector
	_, err := detector.Discover(context.Background(), model.Endpoint{}, confirmedIdentity(), openRoot())
	if err == nil {
		t.Fatal("nil detector Discover() returned nil error")
	}
	ready, err := New(stubProber{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = ready.Discover(nil, model.Endpoint{}, confirmedIdentity(), openRoot())
	if err == nil {
		t.Fatal("Discover(nil context) returned nil error")
	}
}

func TestCapabilityHelpers(t *testing.T) {
	t.Parallel()

	result := emptyResult("9.4.4")
	setCapability(&result, Capability{Name: NameHealth, Availability: AvailabilityUnsupported, StatusCode: 404})
	setCapability(&result, Capability{Name: NameState, Availability: AvailabilityAuthRequired, StatusCode: 401})
	setCapability(&result, Capability{Name: NameNodes, Availability: AvailabilityAvailable, StatusCode: 200})
	if !result.Suppresses(NameHealth) || result.Exists(NameHealth) {
		t.Fatalf("health helpers failed: %#v", result)
	}
	if result.Suppresses(NameState) || !result.Exists(NameState) || result.IsAvailable(NameState) {
		t.Fatalf("state helpers failed: %#v", result)
	}
	if !result.IsAvailable(NameNodes) || result.AvailabilityOf(NameCat) != AvailabilityUnknown {
		t.Fatalf("nodes/cat helpers failed: %#v", result)
	}
}

func FuzzDiscoverStatuses(f *testing.F) {
	f.Add(200, []byte(`{"ok":true}`))
	f.Add(401, []byte(`{"error":"auth"}`))
	f.Add(404, []byte("missing"))
	f.Add(503, []byte("busy"))
	f.Add(0, []byte{0xff, 0xfe})
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		if status < 0 || status > 599 || len(body) > 64*1024 {
			t.Skip()
		}
		detector, err := New(stubProber{fn: func(context.Context, model.Endpoint) (probe.Result, error) {
			return probe.Result{StatusCode: status, Body: body}, nil
		}})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		result, err := detector.Discover(
			context.Background(),
			model.Endpoint{Scheme: model.SchemeHTTP, Host: "127.0.0.1", Port: 9200},
			confirmedIdentity(),
			probe.Result{StatusCode: status, Body: body},
		)
		if err != nil {
			t.Fatalf("Discover() error = %v", err)
		}
		if len(result.Capabilities) != len(reportOrder) {
			t.Fatalf("capabilities = %d", len(result.Capabilities))
		}
		for _, capability := range result.Capabilities {
			switch capability.Availability {
			case AvailabilityUnknown, AvailabilityAvailable, AvailabilityAuthRequired, AvailabilityUnsupported, AvailabilityError:
			default:
				t.Fatalf("invalid availability %q", capability.Availability)
			}
		}
	})
}

type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Accept string
}

type requestRecorder struct {
	mu       sync.Mutex
	requests []recordedRequest
}

func newRequestRecorder() *requestRecorder {
	return &requestRecorder{}
}

func (recorder *requestRecorder) handler(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		recorder.mu.Lock()
		recorder.requests = append(recorder.requests, recordedRequest{
			Method: request.Method,
			Path:   request.URL.Path,
			Query:  request.URL.RawQuery,
			Accept: request.Header.Get("Accept"),
		})
		recorder.mu.Unlock()
		next(writer, request)
	})
}

func (recorder *requestRecorder) snapshot() []recordedRequest {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	cloned := make([]recordedRequest, len(recorder.requests))
	copy(cloned, recorder.requests)
	return cloned
}

type stubProber struct {
	fn func(context.Context, model.Endpoint) (probe.Result, error)
}

func (prober stubProber) Probe(ctx context.Context, endpoint model.Endpoint) (probe.Result, error) {
	if prober.fn == nil {
		return probe.Result{StatusCode: http.StatusOK}, nil
	}
	return prober.fn(ctx, endpoint)
}

func discover(
	t *testing.T,
	detector *Detector,
	endpoint model.Endpoint,
	identity fingerprint.Result,
	root probe.Result,
) (Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return detector.Discover(ctx, endpoint, identity, root)
}

func confirmedIdentity() fingerprint.Result {
	return fingerprint.Result{
		Product:        "Elasticsearch",
		Version:        "9.4.4",
		Score:          100,
		Classification: fingerprint.ClassificationConfirmed,
		Detected:       true,
		Threshold:      80,
	}
}

func openRoot() probe.Result {
	return probe.Result{
		StatusCode: http.StatusOK,
		Headers:    []probe.HeaderField{{Name: "Content-Type", Values: []string{"application/json"}}},
		Body:       []byte(`{"tagline":"You Know, for Search","version":{"number":"9.4.4"}}`),
	}
}

func newTestDetector(t *testing.T) *Detector {
	t.Helper()
	options, err := transport.OptionsFromConfig(config.Defaults(), "garga/capability-test")
	if err != nil {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
	options.DisableEnvironmentProxy = true
	options.RequestTimeout = time.Second
	options.ResponseHeaderTimeout = time.Second
	factory, err := transport.NewFactory(options)
	if err != nil {
		t.Fatalf("NewFactory() error = %v", err)
	}
	t.Cleanup(factory.CloseIdleConnections)
	prober, err := probe.NewHTTP(factory.Client())
	if err != nil {
		t.Fatalf("NewHTTP() error = %v", err)
	}
	detector, err := New(prober)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return detector
}

func endpointForServer(t *testing.T, rawURL string) model.Endpoint {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	var portNumber int
	if _, err := fmt.Sscanf(request.URL.Port(), "%d", &portNumber); err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	scheme := model.SchemeHTTP
	if request.URL.Scheme == "https" {
		scheme = model.SchemeHTTPS
	}
	return model.Endpoint{Scheme: scheme, Host: request.URL.Hostname(), Port: portNumber}
}

func assertAvailability(t *testing.T, result Result, want map[Name]Availability) {
	t.Helper()
	for name, availability := range want {
		if got := result.AvailabilityOf(name); got != availability {
			t.Fatalf("%s = %q, want %q", name, got, availability)
		}
	}
}

func assertSafeRequests(t *testing.T, requests []recordedRequest, prefix string) {
	t.Helper()
	allowed := map[string]struct{}{
		pathHealth:   {},
		pathState:    {},
		pathNodes:    {},
		pathCat:      {},
		pathIndices:  {},
		pathSecurity: {},
	}
	if len(requests) == 0 {
		t.Fatal("no capability requests were issued")
	}
	for _, request := range requests {
		if request.Method != http.MethodGet {
			t.Fatalf("non-GET request: %#v", request)
		}
		if request.Query != "" {
			t.Fatalf("query string is not allowlisted: %#v", request)
		}
		if request.Accept != "application/json" {
			t.Fatalf("Accept = %q, want application/json", request.Accept)
		}
		path := request.Path
		if prefix != "" {
			if !strings.HasPrefix(path, prefix) {
				t.Fatalf("path %q missing prefix %q", path, prefix)
			}
			path = strings.TrimPrefix(path, prefix)
		}
		if _, ok := allowed[path]; !ok {
			t.Fatalf("path %q is not in the GET allowlist", request.Path)
		}
	}
}

func assertNoCanary(t *testing.T, result Result) {
	t.Helper()
	if got := fmt.Sprintf("%+v", result); strings.Contains(got, canary) {
		t.Fatalf("capability result exposed canary: %s", got)
	}
}
