package advisory

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/vulnerability"
)

func TestParseRetryAfterIsBounded(t *testing.T) {
	t.Parallel()

	now := time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{name: "seconds", value: "2", want: 2 * time.Second},
		{name: "maximum", value: "600", want: 30 * time.Second},
		{name: "overflow", value: "999999999999999999", want: 30 * time.Second},
		{name: "http date", value: now.Add(3 * time.Second).Format(http.TimeFormat), want: 3 * time.Second},
		{name: "invalid", value: "later", want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := parseRetryAfter(test.value, now); got != test.want {
				t.Fatalf("parseRetryAfter(%q) = %s, want %s", test.value, got, test.want)
			}
		})
	}
}

func TestDecodeStrictJSONRejectsTrailingDocuments(t *testing.T) {
	t.Parallel()

	var target map[string]any
	if err := decodeStrictJSON([]byte(`{"valid":true}{"trailing":true}`), &target); err == nil {
		t.Fatal("decodeStrictJSON() accepted trailing JSON")
	}
}

func TestFetchEPSSRejectsNonFiniteScores(t *testing.T) {
	t.Parallel()

	const address = "https://first.test/epss.csv.gz"
	contents := gzipCSV(t, "#model_version:test,score_date:2099-01-02T12:00:00Z\n"+
		"cve,epss,percentile\n"+existingCVE+",NaN,0.9\n")
	_, _, err := fetchEPSS(context.Background(), mapFetcher{address: contents}, address, map[string]struct{}{existingCVE: {}})
	if err == nil || !strings.Contains(err.Error(), "score is invalid") {
		t.Fatalf("fetchEPSS(NaN) error = %v", err)
	}
}

const (
	existingCVE = "CVE-2099-1111"
	missingCVE  = "CVE-2099-2222"
)

type mapFetcher map[string][]byte

func (fetcher mapFetcher) Get(_ context.Context, address string, limit int64) ([]byte, error) {
	contents, exists := fetcher[address]
	if !exists {
		return nil, fmt.Errorf("unexpected URL %s", address)
	}
	if int64(len(contents)) > limit {
		return nil, fmt.Errorf("response too large")
	}
	return append([]byte(nil), contents...), nil
}

func TestSyncGeneratesValidatedCandidatesAndBuildsEnrichedCorpus(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	signatureDir := filepath.Join(directory, "signatures")
	if err := os.Mkdir(signatureDir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	writeExistingSignature(t, filepath.Join(signatureDir, "existing.yaml"))
	categoryURL := "https://elastic.test/category.json"
	cveBaseURL := "https://cve.test/api/"
	kevURL := "https://cisa.test/kev.json"
	epssURL := "https://first.test/epss.csv.gz"
	fetcher := mapFetcher{
		categoryURL:                      categoryDocument(t),
		"https://elastic.test/t/42.json": topicDocument(t),
		cveBaseURL + existingCVE:         cveDocument(t, existingCVE, true),
		cveBaseURL + missingCVE:          cveDocument(t, missingCVE, true),
		kevURL:                           []byte(`{"vulnerabilities":[{"cveID":"` + existingCVE + `"}]}`),
		epssURL:                          epssDocument(t),
	}
	candidateDir := filepath.Join(directory, "candidates")
	result, err := Sync(context.Background(), Options{
		SignatureDir: signatureDir, CandidateDir: candidateDir, ElasticCategoryURL: categoryURL,
		CVEAPIBase: cveBaseURL, KEVURL: kevURL, EPSSURL: epssURL, MaxPages: 1, Fetcher: fetcher,
	})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	wantSummary := Summary{Advisories: 2, Present: 1, Ready: 1, Blocked: 0}
	if result.Snapshot.Summary != wantSummary {
		t.Fatalf("summary = %#v, want %#v", result.Snapshot.Summary, wantSummary)
	}
	if result.Snapshot.AsOf != "2099-01-02" {
		t.Fatalf("as_of = %q", result.Snapshot.AsOf)
	}
	if len(result.WrittenCandidates) != 1 || result.WrittenCandidates[0] != "cve-2099-2222.yaml" {
		t.Fatalf("written candidates = %#v", result.WrittenCandidates)
	}
	if _, err := vulnerability.LoadDir(candidateDir); err != nil {
		t.Fatalf("LoadDir(candidates) error = %v", err)
	}

	corpusDir := filepath.Join(directory, "corpus")
	corpus, err := BuildCorpus(signatureDir, corpusDir, result.Snapshot.Advisories, true)
	if err != nil {
		t.Fatalf("BuildCorpus() error = %v", err)
	}
	if len(corpus.Added) != 1 || len(corpus.Updated) != 1 {
		t.Fatalf("corpus result = %#v", corpus)
	}
	signatures, err := vulnerability.LoadDir(corpusDir)
	if err != nil {
		t.Fatalf("LoadDir(corpus) error = %v", err)
	}
	if len(signatures) != 2 {
		t.Fatalf("corpus signatures = %d, want 2", len(signatures))
	}
	foundThreat := false
	for _, signature := range signatures {
		if len(signature.CVE) == 1 && signature.CVE[0] == existingCVE {
			foundThreat = signature.Threat.KnownExploited && signature.Threat.EPSS != nil && *signature.Threat.EPSS == 0.8
		}
	}
	if !foundThreat {
		t.Fatal("existing signature was not enriched with KEV and EPSS")
	}
}

func TestSyncBlocksUnsafeCVEVersionData(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	signatureDir := filepath.Join(directory, "signatures")
	if err := os.Mkdir(signatureDir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	writeExistingSignature(t, filepath.Join(signatureDir, "existing.yaml"))
	categoryURL := "https://elastic.test/category.json"
	cveBaseURL := "https://cve.test/api/"
	kevURL := "https://cisa.test/kev.json"
	epssURL := "https://first.test/epss.csv.gz"
	fetcher := mapFetcher{
		categoryURL:                      categoryDocumentFor(t, 42, missingCVE),
		"https://elastic.test/t/42.json": topicDocumentFor(t, missingCVE),
		cveBaseURL + existingCVE:         cveDocument(t, existingCVE, true),
		cveBaseURL + missingCVE:          cveDocument(t, missingCVE, false),
		kevURL:                           []byte(`{"vulnerabilities":[{"cveID":"CVE-2000-0001"}]}`),
		epssURL:                          epssDocument(t),
	}
	result, err := Sync(context.Background(), Options{
		SignatureDir: signatureDir, ElasticCategoryURL: categoryURL, CVEAPIBase: cveBaseURL,
		KEVURL: kevURL, EPSSURL: epssURL, MaxPages: 1, Fetcher: fetcher,
	})
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if result.Snapshot.Summary.Blocked != 1 || result.Snapshot.Advisories[1].CandidateReason == "" {
		t.Fatalf("blocked advisory = %#v", result.Snapshot.Advisories)
	}
}

func TestBuildCorpusDoesNotOverwriteOutput(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	output := filepath.Join(directory, "output")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatalf("Mkdir(source) error = %v", err)
	}
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatalf("Mkdir(output) error = %v", err)
	}
	writeExistingSignature(t, filepath.Join(source, "existing.yaml"))
	if _, err := BuildCorpus(source, output, nil, false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("BuildCorpus(existing output) error = %v", err)
	}
}

func categoryDocument(t *testing.T) []byte {
	t.Helper()
	return categoryDocumentFor(t, 42, existingCVE+" "+missingCVE)
}

func categoryDocumentFor(t *testing.T, id int, cves string) []byte {
	t.Helper()
	document := map[string]any{"topic_list": map[string]any{
		"more_topics_url": "",
		"topics": []map[string]any{{
			"id": id, "title": "Elasticsearch 9.9.9 Security Update (ESA-2099-01) " + cves,
			"slug": "elasticsearch-security-update", "created_at": "2099-01-01T00:00:00Z",
		}},
	}}
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal(category) error = %v", err)
	}
	return contents
}

func topicDocument(t *testing.T) []byte {
	t.Helper()
	return topicDocumentFor(t, existingCVE+" "+missingCVE)
}

func topicDocumentFor(t *testing.T, cves string) []byte {
	t.Helper()
	document := map[string]any{"post_stream": map[string]any{"posts": []map[string]any{{"cooked": "CVE ID: " + cves}}}}
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal(topic) error = %v", err)
	}
	return contents
}

func cveDocument(t *testing.T, cve string, safe bool) []byte {
	t.Helper()
	defaultStatus := "unaffected"
	if !safe {
		defaultStatus = "affected"
	}
	document := map[string]any{
		"cveMetadata": map[string]any{
			"cveId": cve, "datePublished": "2099-01-01T00:00:00Z", "dateUpdated": "2099-01-02T00:00:00Z",
		},
		"containers": map[string]any{"cna": map[string]any{
			"title":        "Elasticsearch test vulnerability",
			"descriptions": []map[string]any{{"lang": "en", "value": "A bounded test description."}},
			"affected": []map[string]any{{
				"product": "Elasticsearch", "defaultStatus": defaultStatus,
				"versions": []map[string]any{{
					"version": "8.0.0", "lessThan": "8.19.20", "status": "affected", "versionType": "semver",
				}},
			}},
			"metrics":    []map[string]any{{"cvssV3_1": map[string]any{"baseScore": 8.1, "baseSeverity": "HIGH"}}},
			"references": []map[string]any{{"url": "https://example.com/" + cve}},
		}},
	}
	contents, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("json.Marshal(CVE) error = %v", err)
	}
	return contents
}

func epssDocument(t *testing.T) []byte {
	t.Helper()
	return gzipCSV(t,
		"#model_version:test,score_date:2099-01-02T12:00:00Z\n"+
			"cve,epss,percentile\n"+
			existingCVE+",0.8,0.9\n"+
			missingCVE+",0.2,0.4\n",
	)
}

func gzipCSV(t *testing.T, contents string) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	_, err := writer.Write([]byte(contents))
	if err != nil {
		t.Fatalf("gzip Write() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("gzip Close() error = %v", err)
	}
	return output.Bytes()
}

func writeExistingSignature(t *testing.T, path string) {
	t.Helper()
	contents := []byte(`schema_version: "0.1"
id: garga.vuln.cve-2099-1111
title: Existing Elasticsearch test vulnerability
severity: medium
cve:
  - CVE-2099-1111
product: elasticsearch
affected:
  - ">=8.0.0 <8.19.20"
detection: version
references:
  - "https://example.com/CVE-2099-1111"
remediation: Upgrade Elasticsearch.
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile(signature) error = %v", err)
	}
}
