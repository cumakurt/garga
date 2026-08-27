package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/fingerprint"
	"github.com/cumakurt/garga/internal/report"
	"github.com/cumakurt/garga/internal/target"
)

func TestFingerprintEmitsConfirmedIdentityWithoutExtraProbes(t *testing.T) {
	clearProxyEnv(t)

	recorder := newMethodRecorder()
	server := httptest.NewServer(recorder.handler(openElasticsearchHandler()))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	result, err := Fingerprint(context.Background(), testScanOptions(t, server.URL, &stdout))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result.Identities != 1 || result.Findings != 0 {
		t.Fatalf("identities=%d findings=%d", result.Identities, result.Findings)
	}

	var identity Identity
	if err := json.Unmarshal(stdout.Bytes(), &identity); err != nil {
		t.Fatalf("Unmarshal() error = %v stdout = %s", err, stdout.String())
	}
	if !identity.Detected || identity.Product != "Elasticsearch" || identity.Version != "8.19.19" {
		t.Fatalf("identity = %#v", identity)
	}
	if identity.Classification != string(fingerprint.ClassificationConfirmed) {
		t.Fatalf("classification = %q", identity.Classification)
	}
	if strings.Contains(stdout.String(), "fixture-cluster") || strings.Contains(stdout.String(), "fixture-node") {
		t.Fatalf("identity leaked cluster identity: %s", stdout.String())
	}

	requests := recorder.snapshot()
	if len(requests) != 1 || requests[0].Method != http.MethodGet || requests[0].Path != "/" {
		t.Fatalf("requests = %#v, want a single GET /", requests)
	}
}

func TestFingerprintEmitsUnknownIdentityForNonElasticsearch(t *testing.T) {
	clearProxyEnv(t)

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "<html>nginx</html>")
	}))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	result, err := Fingerprint(context.Background(), testScanOptions(t, server.URL, &stdout))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result.Identities != 1 {
		t.Fatalf("identities = %d", result.Identities)
	}
	var identity Identity
	if err := json.Unmarshal(stdout.Bytes(), &identity); err != nil {
		t.Fatalf("Unmarshal() error = %v stdout = %s", err, stdout.String())
	}
	if identity.Detected || identity.Product != "" {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestFingerprintRejectsHTMLFormat(t *testing.T) {
	t.Parallel()

	source, err := target.NewReaderSource(strings.NewReader("http://127.0.0.1:9200\n"), "cli")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	_, err = Fingerprint(context.Background(), Options{
		Config: testConfig(),
		Source: source,
		Output: io.Discard,
		Format: report.FormatHTML,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Fingerprint() error = %v, want ErrInvalidInput", err)
	}
}

func TestFingerprintHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source, err := target.NewReaderSource(strings.NewReader("http://127.0.0.1:1\n"), "cli")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	_, err = Fingerprint(ctx, Options{
		Config: testConfig(),
		Source: source,
		Output: io.Discard,
		Format: report.FormatJSONL,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Fingerprint() error = %v, want context.Canceled", err)
	}
}

func TestFingerprintCountsUnreachableTargetsAsFailures(t *testing.T) {
	clearProxyEnv(t)

	server := httptest.NewServer(openElasticsearchHandler())
	t.Cleanup(server.Close)

	input := server.URL + "\nhttp://127.0.0.1:1\n"
	source, err := target.NewReaderSource(strings.NewReader(input), "cli")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	result, err := Fingerprint(context.Background(), Options{
		Config: testConfig(),
		Source: source,
		Output: io.Discard,
		Format: report.FormatJSONL,
	})
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result.Stats.Succeeded != 1 || result.Stats.Failed != 1 || result.Identities != 1 {
		t.Fatalf("succeeded=%d failed=%d identities=%d", result.Stats.Succeeded, result.Stats.Failed, result.Identities)
	}
}
