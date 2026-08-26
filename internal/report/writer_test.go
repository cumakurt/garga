package report

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/model"
)

const xssTitle = "</td><script>alert(1)</script>"

func sampleFindings() []model.Finding {
	endpoint := model.Endpoint{Scheme: model.SchemeHTTP, Host: "192.168.1.10", Port: 9200}
	return []model.Finding{
		{
			ID:          "garga.tls.not_enabled|http://192.168.1.10:9200/|",
			CheckID:     "garga.tls.not_enabled",
			Title:       "Elasticsearch is reachable over HTTP",
			Target:      endpoint,
			Product:     "elasticsearch",
			Severity:    model.SeverityMedium,
			Confidence:  model.ConfidenceHigh,
			Evidence:    []model.Evidence{{Code: "scheme-http"}},
			Remediation: "Serve Elasticsearch only over HTTPS.",
		},
		{
			ID:          "garga.exposure.anonymous_access|http://192.168.1.10:9200/|",
			CheckID:     "garga.exposure.anonymous_access",
			Title:       xssTitle,
			Target:      endpoint,
			Product:     "elasticsearch",
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceMedium,
			Evidence:    []model.Evidence{{Code: "anonymous-metadata"}},
			Remediation: "=cmd|'/c calc'!A0",
			Tags:        []string{"exposure"},
		},
	}
}

func renderFormat(t *testing.T, format Format, findings []model.Finding) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := New(format, &output)
	if err != nil {
		t.Fatalf("New(%q) error = %v", format, err)
	}
	for _, finding := range findings {
		if writeErr := writer.Write(context.Background(), finding); writeErr != nil {
			t.Fatalf("Write(%q) error = %v", format, writeErr)
		}
	}
	if closeErr := writer.Close(); closeErr != nil {
		t.Fatalf("Close(%q) error = %v", format, closeErr)
	}
	return output.Bytes()
}

func TestParseFormat(t *testing.T) {
	t.Parallel()

	format, err := ParseFormat(" JSONL ")
	if err != nil {
		t.Fatalf("ParseFormat() error = %v", err)
	}
	if format != FormatJSONL {
		t.Fatalf("ParseFormat() = %q, want %q", format, FormatJSONL)
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Fatal("ParseFormat(xml) error = nil, want error")
	}
}

func TestNewRejectsNilOutputAndUnknownFormat(t *testing.T) {
	t.Parallel()

	if _, err := New(FormatJSON, nil); err == nil {
		t.Fatal("New(nil output) error = nil, want error")
	}
	if _, err := New(Format("xml"), io.Discard); err == nil {
		t.Fatal("New(xml) error = nil, want error")
	}
}

func TestJSONAndJSONLParseWithStableFieldNames(t *testing.T) {
	t.Parallel()

	findings := sampleFindings()
	jsonOutput := renderFormat(t, FormatJSON, findings)
	var document struct {
		SchemaVersion string          `json:"schema_version"`
		Findings      []model.Finding `json:"findings"`
	}
	if err := json.Unmarshal(jsonOutput, &document); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; payload = %s", err, jsonOutput)
	}
	if document.SchemaVersion != model.FindingSchemaVersion {
		t.Fatalf("document schema_version = %q, want %q", document.SchemaVersion, model.FindingSchemaVersion)
	}
	if len(document.Findings) != len(findings) {
		t.Fatalf("findings = %d, want %d", len(document.Findings), len(findings))
	}
	if document.Findings[0].CheckID != findings[0].CheckID {
		t.Fatalf("first check_id = %q, want %q", document.Findings[0].CheckID, findings[0].CheckID)
	}
	if document.Findings[1].Title != xssTitle {
		t.Fatalf("xss title round-trip = %q", document.Findings[1].Title)
	}

	var first map[string]json.RawMessage
	if err := json.Unmarshal(mustFirstJSONObject(t, jsonOutput), &first); err != nil {
		t.Fatalf("first finding object: %v", err)
	}
	for _, key := range []string{
		"schema_version", "id", "check_id", "title", "target", "product", "severity", "confidence", "evidence", "remediation",
	} {
		if _, ok := first[key]; !ok {
			t.Errorf("JSON finding missing field %q", key)
		}
	}
	var target map[string]json.RawMessage
	if err := json.Unmarshal(first["target"], &target); err != nil {
		t.Fatalf("target: %v", err)
	}
	for _, key := range []string{"scheme", "host", "port"} {
		if _, ok := target[key]; !ok {
			t.Errorf("JSON target missing field %q", key)
		}
	}

	jsonlOutput := renderFormat(t, FormatJSONL, findings)
	lines := bytes.Split(bytes.TrimSpace(jsonlOutput), []byte("\n"))
	if len(lines) != len(findings) {
		t.Fatalf("JSONL lines = %d, want %d", len(lines), len(findings))
	}
	for index, line := range lines {
		var finding model.Finding
		if err := json.Unmarshal(line, &finding); err != nil {
			t.Fatalf("JSONL line %d: %v; payload = %s", index+1, err, line)
		}
		if finding.SchemaVersion != model.FindingSchemaVersion {
			t.Errorf("JSONL schema_version = %q, want %q", finding.SchemaVersion, model.FindingSchemaVersion)
		}
		if finding.CheckID != findings[index].CheckID {
			t.Errorf("JSONL check_id = %q, want %q", finding.CheckID, findings[index].CheckID)
		}
	}
}

func TestJSONLAndJSONWritersDoNotRetainFindings(t *testing.T) {
	t.Parallel()

	jsonl, err := New(FormatJSONL, io.Discard)
	if err != nil {
		t.Fatalf("New(jsonl) error = %v", err)
	}
	assertNoFindingSlice(t, jsonl)

	jsonWriter, err := New(FormatJSON, io.Discard)
	if err != nil {
		t.Fatalf("New(json) error = %v", err)
	}
	assertNoFindingSlice(t, jsonWriter)
}

func TestHTMLEscapesContentAndHasNoNetworkDependency(t *testing.T) {
	t.Parallel()

	output := string(renderFormat(t, FormatHTML, sampleFindings()))
	if strings.Contains(output, "</td><script>") || strings.Contains(output, "<script>") {
		t.Fatalf("HTML did not escape XSS payload: %s", output)
	}
	escaped := html.EscapeString(xssTitle)
	if !strings.Contains(output, escaped) {
		t.Fatalf("HTML missing escaped title %q in %s", escaped, output)
	}

	lower := strings.ToLower(output)
	for _, needle := range []string{"<script", "<link", "<img", "<iframe", "src=", "href=", "@import", "url("} {
		if strings.Contains(lower, needle) {
			t.Errorf("HTML contains network-capable construct %q", needle)
		}
	}
	if !strings.Contains(output, "<style>") {
		t.Fatal("HTML missing inline CSS")
	}
}

func TestCSVNeutralizesFormulaInjection(t *testing.T) {
	t.Parallel()

	output := string(renderFormat(t, FormatCSV, sampleFindings()))
	if strings.Contains(output, "\n=cmd") || strings.Contains(output, ",=cmd") {
		t.Fatalf("CSV leaked formula payload: %s", output)
	}
	if !strings.Contains(output, "'=cmd|'/c calc'!A0") {
		t.Fatalf("CSV missing neutralized formula: %s", output)
	}
}

func TestDeterministicFormatsAreStable(t *testing.T) {
	t.Parallel()

	findings := sampleFindings()
	for _, format := range []Format{FormatConsole, FormatJSON, FormatJSONL, FormatCSV, FormatHTML} {
		first := renderFormat(t, format, findings)
		second := renderFormat(t, format, findings)
		if !bytes.Equal(first, second) {
			t.Errorf("%s output is not deterministic", format)
		}
	}
}

func TestWritersMatchGoldenFixtures(t *testing.T) {
	findings := sampleFindings()
	for _, format := range []Format{FormatConsole, FormatJSON, FormatJSONL, FormatCSV, FormatHTML} {
		got := renderFormat(t, format, findings)
		path := filepath.Join("testdata", "two-findings."+string(format))
		if os.Getenv("GARGA_WRITE_GOLDEN") == "1" {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatalf("MkdirAll() error = %v", err)
			}
			if err := os.WriteFile(path, got, 0o644); err != nil {
				t.Fatalf("WriteFile(%s) error = %v", path, err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s golden mismatch\ngot:\n%s\nwant:\n%s", format, got, want)
		}
	}
}

func TestJSONEmptyDocument(t *testing.T) {
	t.Parallel()

	output := renderFormat(t, FormatJSON, nil)
	want := `{"schema_version":"` + model.FindingSchemaVersion + `","findings":[]}` + "\n"
	if string(output) != want {
		t.Fatalf("empty JSON = %q, want %q", output, want)
	}
}

func TestDecodeJSONLStreamsRecords(t *testing.T) {
	t.Parallel()

	input := renderFormat(t, FormatJSONL, sampleFindings())
	var got []model.Finding
	err := DecodeJSONL(context.Background(), bytes.NewReader(input), func(finding model.Finding) error {
		got = append(got, finding)
		return nil
	})
	if err != nil {
		t.Fatalf("DecodeJSONL() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("decoded %d findings, want 2", len(got))
	}
	if got[1].Title != xssTitle {
		t.Fatalf("decoded title = %q", got[1].Title)
	}
}

func TestDecodeJSONLRejectsInvalidRecordsWithoutEchoingPayload(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	err := DecodeJSONL(context.Background(), strings.NewReader(`{"check_id":`+canary+`}`+"\n"), func(model.Finding) error {
		t.Fatal("emit must not run for invalid JSON")
		return nil
	})
	if err == nil {
		t.Fatal("DecodeJSONL() error = nil, want error")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("decode error echoed payload: %v", err)
	}
}

func TestDecodeJSONLRejectsOversizedLine(t *testing.T) {
	t.Parallel()

	line := bytes.Repeat([]byte("a"), MaxFindingLineBytes+1)
	line = append(line, '\n')
	err := DecodeJSONL(context.Background(), bytes.NewReader(line), func(model.Finding) error {
		return nil
	})
	if err == nil {
		t.Fatal("DecodeJSONL() error = nil, want oversized-line error")
	}
	if !strings.Contains(err.Error(), "line limit") {
		t.Fatalf("error = %v, want line limit", err)
	}
}

func TestWriteHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	writer, err := New(FormatJSONL, io.Discard)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if writeErr := writer.Write(ctx, sampleFindings()[0]); writeErr == nil {
		t.Fatal("Write() error = nil, want canceled context")
	}
}

func TestJSONWriteAfterClose(t *testing.T) {
	t.Parallel()

	writer, err := New(FormatJSON, io.Discard)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if writeErr := writer.Write(context.Background(), sampleFindings()[0]); writeErr == nil {
		t.Fatal("Write() after Close() error = nil, want error")
	}
}

func mustFirstJSONObject(t *testing.T, document []byte) []byte {
	t.Helper()
	var parsed struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(document, &parsed); err != nil {
		t.Fatalf("document: %v", err)
	}
	if len(parsed.Findings) == 0 {
		t.Fatal("document has no findings")
	}
	return parsed.Findings[0]
}

func assertNoFindingSlice(t *testing.T, writer Writer) {
	t.Helper()
	value := reflect.ValueOf(writer)
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	findingType := reflect.TypeOf(model.Finding{})
	for index := 0; index < value.NumField(); index++ {
		field := value.Type().Field(index)
		if field.Type.Kind() == reflect.Slice && field.Type.Elem() == findingType {
			t.Errorf("writer retains findings in field %s", field.Name)
		}
	}
}
