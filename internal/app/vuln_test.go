package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/checks"
	"github.com/cumakurt/garga/internal/report"
	"github.com/cumakurt/garga/internal/target"
)

func TestVulnEmitsSignatureFindingsWithoutExposureChecks(t *testing.T) {
	clearProxyEnv(t)

	recorder := newMethodRecorder()
	server := httptest.NewServer(recorder.handler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		writer.WriteHeader(http.StatusOK)
		body := strings.Replace(elasticsearchRootBody, "8.19.19", "9.4.4", 1)
		if request.URL.Path == "/" || request.URL.Path == "" {
			_, _ = io.WriteString(writer, body)
			return
		}
		_, _ = io.WriteString(writer, `{"status":"green"}`)
	})))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	options := testScanOptions(t, server.URL, &stdout)
	options.SignatureDir = versionOnlySignatureDir(t)
	result, err := Vuln(context.Background(), options)
	if err != nil {
		t.Fatalf("Vuln() error = %v", err)
	}
	if result.Findings == 0 {
		t.Fatal("expected signature findings")
	}
	ids := findingCheckIDs(t, stdout.Bytes())
	if !ids["garga.vuln.example-version-only-94"] {
		t.Fatalf("missing signature finding: %v", ids)
	}
	if ids[checks.CheckTLSNotEnabled] || ids[checks.CheckExposureAnonymousAccess] {
		t.Fatalf("exposure checks leaked: %v", ids)
	}
	assertGetOnlyAllowlisted(t, recorder.snapshot())
}

func TestVulnUsesBundledCorpusWhenSignatureDirOmitted(t *testing.T) {
	clearProxyEnv(t)

	recorder := newMethodRecorder()
	server := httptest.NewServer(recorder.handler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		writer.WriteHeader(http.StatusOK)
		body := strings.Replace(elasticsearchRootBody, "8.19.19", "8.8.0", 1)
		if request.URL.Path == "/" || request.URL.Path == "" {
			_, _ = io.WriteString(writer, body)
			return
		}
		_, _ = io.WriteString(writer, `{"status":"green"}`)
	})))
	t.Cleanup(server.Close)

	var stdout bytes.Buffer
	options := testScanOptions(t, server.URL, &stdout)
	result, err := Vuln(context.Background(), options)
	if err != nil {
		t.Fatalf("Vuln() error = %v", err)
	}
	if result.Findings == 0 {
		t.Fatal("expected bundled signature findings")
	}
	ids := findingCheckIDs(t, stdout.Bytes())
	if !ids["garga.vuln.cve-2023-31418"] {
		t.Fatalf("missing bundled CVE finding: %v", ids)
	}
	if ids[checks.CheckTLSNotEnabled] || ids[checks.CheckExposureAnonymousAccess] {
		t.Fatalf("exposure checks leaked: %v", ids)
	}
	assertGetOnlyAllowlisted(t, recorder.snapshot())
}

func TestVulnRejectsEmptySignatureDirectory(t *testing.T) {
	t.Parallel()

	source, err := target.NewReaderSource(strings.NewReader("http://127.0.0.1:9200\n"), "cli")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	_, err = Vuln(context.Background(), Options{
		Config:       testConfig(),
		Source:       source,
		Output:       io.Discard,
		Format:       report.FormatJSONL,
		SignatureDir: t.TempDir(),
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Vuln() error = %v, want ErrInvalidInput", err)
	}
}

func TestVulnHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source, err := target.NewReaderSource(strings.NewReader("http://127.0.0.1:1\n"), "cli")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	_, err = Vuln(ctx, Options{
		Config:       testConfig(),
		Source:       source,
		Output:       io.Discard,
		Format:       report.FormatJSONL,
		SignatureDir: versionOnlySignatureDir(t),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Vuln() error = %v, want context.Canceled", err)
	}
}

func versionOnlySignatureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sourceYAML, err := os.ReadFile(filepath.Join("..", "vulnerability", "testdata", "valid", "example-version-only-94.yaml"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "example-version-only-94.yaml"), sourceYAML, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return dir
}
