package fingerprint

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/probe"
)

func TestSupportedElasticsearchCorpusIsConfirmed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fixture string
		version string
	}{
		{"elasticsearch-7.17.23.json", "7.17.23"},
		{"elasticsearch-8.0.0.json", "8.0.0"},
		{"elasticsearch-8.19.19.json", "8.19.19"},
		{"elasticsearch-9.0.0.json", "9.0.0"},
		{"elasticsearch-9.3.8.json", "9.3.8"},
		{"elasticsearch-9.4.4.json", "9.4.4"},
	}
	engine := defaultEngine(t)
	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			t.Parallel()
			result := engine.Analyze(elasticResponse(readFixture(t, test.fixture), true))
			if !result.Detected || result.Product != productElasticsearch || result.Version != test.version {
				t.Fatalf("Analyze() = %#v", result)
			}
			if result.Score != 100 || result.Classification != ClassificationConfirmed {
				t.Fatalf("score/classification = %d/%s", result.Score, result.Classification)
			}
			assertSignalOrder(t, result.Signals)
		})
	}
}

func TestLegacyRootWithoutProductHeaderIsPossible(t *testing.T) {
	t.Parallel()

	response := elasticResponse(readFixture(t, "elasticsearch-7.17.23.json"), false)
	result := defaultEngine(t).Analyze(response)
	if result.Score != 65 || result.Classification != ClassificationPossible || result.Detected {
		t.Fatalf("default Analyze() = %#v", result)
	}
	legacyEngine, err := New(Options{Threshold: 40})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result = legacyEngine.Analyze(response)
	if !result.Detected || result.Product != productElasticsearch || result.Version != "7.17.23" {
		t.Fatalf("legacy Analyze() = %#v", result)
	}
}

func TestAuthenticationResponseCanConfirmElasticsearch(t *testing.T) {
	t.Parallel()

	response := probe.Result{
		StatusCode: 401,
		Headers: []probe.HeaderField{
			{Name: "Content-Type", Values: []string{"application/json"}},
			{Name: "Www-Authenticate", Values: []string{`Basic realm="security" charset="UTF-8"`, "ApiKey"}},
			{Name: "X-Elastic-Product", Values: []string{"Elasticsearch"}},
		},
	}
	result := defaultEngine(t).Analyze(response)
	if result.Score != 90 || result.Classification != ClassificationConfirmed || !result.Detected {
		t.Fatalf("Analyze() = %#v", result)
	}
}

func TestNegativeCorpusIsNeverConfirmed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		fixture     string
		contentType string
		forgeHeader bool
		wantClass   Classification
	}{
		{"OpenSearch", "opensearch-2.19.0.json", "application/json", true, ClassificationUnknown},
		{"generic JSON", "generic-json.json", "application/json", false, ClassificationUnknown},
		{"Kibana", "kibana-status.json", "application/json", false, ClassificationUnknown},
		{"nginx", "nginx.html", "text/html", false, ClassificationUnknown},
		{"Apache", "apache.html", "text/html", false, ClassificationUnknown},
	}
	engine := defaultEngine(t)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := probe.Result{
				StatusCode: 200,
				Body:       readFixture(t, test.fixture),
				Headers:    []probe.HeaderField{{Name: "Content-Type", Values: []string{test.contentType}}},
			}
			if test.forgeHeader {
				response.Headers = append(response.Headers, probe.HeaderField{Name: "X-Elastic-Product", Values: []string{"Elasticsearch"}})
			}
			result := engine.Analyze(response)
			if result.Detected || result.Product != "" || result.Classification != test.wantClass || result.Score >= 90 {
				t.Fatalf("Analyze() = %#v", result)
			}
		})
	}
}

func TestSingleProductHeaderIsNotConfirmation(t *testing.T) {
	t.Parallel()

	response := probe.Result{
		StatusCode: 200,
		Body:       []byte(`not-json`),
		Headers: []probe.HeaderField{
			{Name: "Content-Type", Values: []string{"application/json"}},
			{Name: "X-Elastic-Product", Values: []string{"elasticsearch"}},
		},
	}
	result := defaultEngine(t).Analyze(response)
	if result.Score != 65 || result.Classification != ClassificationPossible || result.Detected {
		t.Fatalf("Analyze() = %#v", result)
	}
}

func TestMalformedAndTruncatedBodiesDoNotPanic(t *testing.T) {
	t.Parallel()

	tests := [][]byte{
		nil,
		{},
		[]byte("{"),
		[]byte(`{"name":"node","version":{"number":"9.4`),
		[]byte{0xff, 0xfe, 0xfd},
		[]byte(strings.Repeat("[", 10_000)),
	}
	engine := defaultEngine(t)
	for _, body := range tests {
		result := engine.Analyze(probe.Result{Body: body})
		if result.Score != 0 || result.Classification != ClassificationUnknown {
			t.Fatalf("Analyze(%q) = %#v", body, result)
		}
	}
}

func TestFingerprintResultDoesNotRetainArbitraryValues(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	response := probe.Result{
		StatusCode: 200,
		Body:       []byte(`{"name":"` + canary + `","cluster_name":"` + canary + `","version":{"number":"` + canary + `"}}`),
		Headers: []probe.HeaderField{
			{Name: "Server", Values: []string{canary}},
			{Name: "Warning", Values: []string{canary}},
			{Name: "Www-Authenticate", Values: []string{`Basic realm="` + canary + `"`}},
		},
	}
	result := defaultEngine(t).Analyze(response)
	if got := fmt.Sprintf("%+v", result); strings.Contains(got, canary) {
		t.Fatalf("fingerprint result exposed canary: %s", got)
	}
}

func TestEquivalentResponsesAreDeterministic(t *testing.T) {
	t.Parallel()

	response := elasticResponse(readFixture(t, "elasticsearch-9.4.4.json"), true)
	engine := defaultEngine(t)
	first := engine.Analyze(response)
	second := engine.Analyze(response)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Analyze() changed:\n%#v\n%#v", first, second)
	}
}

func TestNilEngineIsSafeAndDoesNotDetect(t *testing.T) {
	t.Parallel()

	var engine *Engine
	result := engine.Analyze(elasticResponse(readFixture(t, "elasticsearch-9.4.4.json"), true))
	if result.Detected || result.Classification != ClassificationUnknown || result.Threshold != 100 {
		t.Fatalf("nil Analyze() = %#v", result)
	}
}

func assertSignalOrder(t *testing.T, signals []Signal) {
	t.Helper()
	want := []string{
		SignalOpenSearchMarker,
		SignalProductHeader,
		SignalTagline,
		SignalVersion,
		SignalBuildMetadata,
		SignalClusterIdentity,
		SignalAuthChallenge,
		SignalWarningHeader,
		SignalJSONContent,
	}
	if len(signals) != len(want) {
		t.Fatalf("signals = %d, want %d", len(signals), len(want))
	}
	for index := range want {
		if signals[index].Name != want[index] {
			t.Fatalf("signal[%d] = %q, want %q", index, signals[index].Name, want[index])
		}
	}
}

func elasticResponse(body []byte, includeProductHeader bool) probe.Result {
	headers := []probe.HeaderField{{Name: "Content-Type", Values: []string{"application/json; charset=UTF-8"}}}
	if includeProductHeader {
		headers = append(headers, probe.HeaderField{Name: "X-Elastic-Product", Values: []string{"Elasticsearch"}})
	}
	return probe.Result{StatusCode: 200, Protocol: "HTTP/1.1", Headers: headers, Body: body}
}

func defaultEngine(t *testing.T) *Engine {
	t.Helper()
	options, err := OptionsFromConfig(config.Defaults())
	if err != nil {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
	engine, err := New(options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return engine
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return contents
}

func FuzzAnalyze(f *testing.F) {
	seed, err := os.ReadFile("testdata/elasticsearch-9.4.4.json")
	if err != nil {
		f.Fatalf("read seed: %v", err)
	}
	f.Add(seed)
	f.Add([]byte(`{"version":{"distribution":"opensearch"}}`))
	f.Add([]byte("{"))
	engine, err := New(Options{Threshold: 80})
	if err != nil {
		f.Fatalf("New() error = %v", err)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1024*1024 {
			t.Skip()
		}
		result := engine.Analyze(probe.Result{
			StatusCode: 200,
			Headers:    []probe.HeaderField{{Name: "Content-Type", Values: []string{"application/json"}}},
			Body:       body,
		})
		if result.Score < 0 || result.Score > 100 {
			t.Fatalf("score = %d", result.Score)
		}
	})
}
