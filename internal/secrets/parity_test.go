package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type outputParity struct {
	Findings           int
	Critical           int
	High               int
	Medium             int
	Low                int
	Info               int
	TargetsScanned     int
	ReachableTargets   int
	IndicesInspected   int
	DocumentsExamined  int
	CorrelatedFindings int
	Occurrences        int
	Categories         map[string]int
	Correlations       map[string]int
}

func TestOutputParityAcrossRenderers(t *testing.T) {
	t.Parallel()
	result := reportFixture()
	canonical := parityFromSummary(result.Summary)
	if canonical.Findings != len(result.Findings) {
		t.Fatalf("canonical findings %d != slice %d", canonical.Findings, len(result.Findings))
	}

	var jsonBuffer, table, pdf bytes.Buffer
	if err := WriteReport(&jsonBuffer, FormatJSON, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteReport(&table, FormatTable, result); err != nil {
		t.Fatal(err)
	}
	if err := WritePDF(&pdf, result); err != nil {
		t.Fatal(err)
	}

	var decoded ScanReport
	if err := json.Unmarshal(jsonBuffer.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	jsonParity := parityFromSummary(decoded.Summary)
	tableParity := parseTableParity(t, table.String())
	pdfParity := parsePDFParity(t, pdf.Bytes())

	assertParityEqual(t, "JSON", canonical, jsonParity)
	assertParityEqual(t, "table", canonical, tableParity)
	assertParityCounters(t, "PDF", canonical, pdfParity)
	if jsonParity.Findings != len(decoded.Findings) {
		t.Fatalf("JSON finding slice %d != summary %d", len(decoded.Findings), jsonParity.Findings)
	}
	if !bytes.Contains(pdf.Bytes(), []byte("Passwords")) {
		t.Fatal("PDF missing Passwords category")
	}
	if !bytes.Contains(pdf.Bytes(), []byte("Username + Password")) {
		t.Fatal("PDF missing Username + Password correlation")
	}
}

func TestFindingSortIsDeterministic(t *testing.T) {
	t.Parallel()
	findings := []Finding{
		{Severity: SeverityLow, Target: "b", Index: "idx", Category: "credential.password", FieldPath: "password", DocumentID: "2", Detector: "sensitive-field", MaskedPreview: "b***"},
		{Severity: SeverityCritical, Target: "a", Index: "idx", Category: "credential.password", FieldPath: "password", DocumentID: "1", Detector: "sensitive-field", MaskedPreview: "a***"},
		{Severity: SeverityHigh, Target: "a", Index: "idx", Category: "credential.pair", FieldPath: "accounts[0]", DocumentID: "3", Detector: "credential-pair", CredentialType: "username_password", MaskedPreview: "u***"},
	}
	first := append([]Finding(nil), findings...)
	second := []Finding{findings[2], findings[0], findings[1]}
	sortFindings(first)
	sortFindings(second)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("sortFindings is input-order dependent:\n first=%#v\nsecond=%#v", first, second)
	}
	if first[0].Severity != SeverityCritical || first[1].Severity != SeverityHigh || first[2].Severity != SeverityLow {
		t.Fatalf("severity order = %v, %v, %v", first[0].Severity, first[1].Severity, first[2].Severity)
	}
}

func parityFromSummary(summary Summary) outputParity {
	return outputParity{
		Findings:           summary.Findings,
		Critical:           summary.SeverityCounts[string(SeverityCritical)],
		High:               summary.SeverityCounts[string(SeverityHigh)],
		Medium:             summary.SeverityCounts[string(SeverityMedium)],
		Low:                summary.SeverityCounts[string(SeverityLow)],
		Info:               summary.SeverityCounts[string(SeverityInfo)],
		TargetsScanned:     summary.TargetsScanned,
		ReachableTargets:   summary.ReachableTargets,
		IndicesInspected:   summary.IndicesInspected,
		DocumentsExamined:  summary.DocumentsExamined,
		CorrelatedFindings: summary.CorrelatedFindings,
		Occurrences:        summary.Occurrences,
		Categories:         cloneCounts(summary.CategoryCounts),
		Correlations:       cloneCounts(summary.CorrelationCounts),
	}
}

func parseTableParity(t *testing.T, text string) outputParity {
	t.Helper()
	parity := outputParity{Categories: map[string]int{}, Correlations: map[string]int{}}
	parity.TargetsScanned = mustLabeledInt(t, text, `(?m)^Targets scanned: (\d+)$`)
	parity.ReachableTargets = mustLabeledInt(t, text, `(?m)^Reachable targets: (\d+)$`)
	parity.IndicesInspected = mustLabeledInt(t, text, `(?m)^Indices inspected: (\d+)$`)
	parity.DocumentsExamined = mustLabeledInt(t, text, `(?m)^Documents examined: (\d+)$`)
	parity.Findings = mustLabeledInt(t, text, `(?m)^Sensitive findings: (\d+)$`)
	parity.Critical = mustLabeledInt(t, text, `(?m)^CRITICAL: (\d+)$`)
	parity.High = mustLabeledInt(t, text, `(?m)^HIGH: (\d+)$`)
	parity.Medium = mustLabeledInt(t, text, `(?m)^MEDIUM: (\d+)$`)
	parity.Low = mustLabeledInt(t, text, `(?m)^LOW: (\d+)$`)
	parity.Info = mustLabeledInt(t, text, `(?m)^INFO: (\d+)$`)
	parity.CorrelatedFindings = mustLabeledInt(t, text, `(?m)^Correlated findings: (\d+)$`)
	parity.Occurrences = mustLabeledInt(t, text, `(?m)^Occurrences: (\d+)$`)
	parity.Categories = parseNamedSection(text, "Categories:")
	parity.Correlations = parseNamedSection(text, "Credential Correlations:")
	return parity
}

func parsePDFParity(t *testing.T, payload []byte) outputParity {
	t.Helper()
	text := string(payload)
	parity := outputParity{Categories: map[string]int{}, Correlations: map[string]int{}}
	targets := regexp.MustCompile(`(\d+) \\?\(reachable (\d+)\\?\)`).FindStringSubmatch(text)
	if len(targets) != 3 {
		t.Fatal("PDF missing targets scanned / reachable")
	}
	parity.TargetsScanned = atoi(t, targets[1])
	parity.ReachableTargets = atoi(t, targets[2])
	parity.IndicesInspected = pdfKVInt(t, payload, "Indices inspected")
	parity.DocumentsExamined = pdfKVInt(t, payload, "Documents examined")
	findings := regexp.MustCompile(`(\d+) \\?\(field \d+, correlated (\d+)\\?\)`).FindStringSubmatch(text)
	if len(findings) != 3 {
		t.Fatal("PDF missing findings / correlated counts")
	}
	parity.Findings = atoi(t, findings[1])
	parity.CorrelatedFindings = atoi(t, findings[2])
	parity.Occurrences = pdfKVInt(t, payload, "Occurrences")
	severity := regexp.MustCompile(`CRITICAL (\d+), HIGH (\d+), MEDIUM (\d+), LOW (\d+), INFO (\d+)`).FindStringSubmatch(text)
	if len(severity) != 6 {
		t.Fatal("PDF missing severity distribution")
	}
	parity.Critical = atoi(t, severity[1])
	parity.High = atoi(t, severity[2])
	parity.Medium = atoi(t, severity[3])
	parity.Low = atoi(t, severity[4])
	parity.Info = atoi(t, severity[5])
	return parity
}

func pdfKVInt(t *testing.T, payload []byte, key string) int {
	t.Helper()
	pattern := regexp.MustCompile(regexp.QuoteMeta(key) + `\)[\s\S]{0,400}?\((\d+)\)`)
	match := pattern.FindSubmatch(payload)
	if len(match) != 2 {
		t.Fatalf("PDF missing %q value", key)
	}
	return atoi(t, string(match[1]))
}

func assertParityCounters(t *testing.T, name string, want, got outputParity) {
	t.Helper()
	if want.Findings != got.Findings || want.Critical != got.Critical || want.High != got.High ||
		want.Medium != got.Medium || want.Low != got.Low || want.Info != got.Info ||
		want.TargetsScanned != got.TargetsScanned || want.ReachableTargets != got.ReachableTargets ||
		want.IndicesInspected != got.IndicesInspected || want.DocumentsExamined != got.DocumentsExamined ||
		want.CorrelatedFindings != got.CorrelatedFindings || want.Occurrences != got.Occurrences {
		t.Fatalf("%s counters mismatch\n want: %#v\n  got: %#v", name, want, got)
	}
}

func assertParityEqual(t *testing.T, name string, want, got outputParity) {
	t.Helper()
	assertParityCounters(t, name, want, got)
	for key, count := range want.Categories {
		if got.Categories[key] != count {
			t.Fatalf("%s category %q: got %d want %d", name, key, got.Categories[key], count)
		}
	}
	for key, count := range want.Correlations {
		if got.Correlations[key] != count {
			t.Fatalf("%s correlation %q: got %d want %d", name, key, got.Correlations[key], count)
		}
	}
}

func parseNamedSection(text, heading string) map[string]int {
	counts := map[string]int{}
	index := strings.Index(text, heading)
	if index < 0 {
		return counts
	}
	rest := text[index+len(heading):]
	for _, line := range strings.Split(rest, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			if len(counts) > 0 {
				break
			}
			continue
		}
		if strings.HasSuffix(line, ":") {
			break
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		value := strings.TrimSpace(parts[len(parts)-1])
		number, err := strconv.Atoi(value)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(strings.Join(parts[:len(parts)-1], ":"))
		if name != "" {
			counts[name] = number
		}
	}
	return counts
}

func mustLabeledInt(t *testing.T, text, pattern string) int {
	t.Helper()
	match := regexp.MustCompile(pattern).FindStringSubmatch(text)
	if len(match) != 2 {
		t.Fatalf("pattern %s did not match", pattern)
	}
	return atoi(t, match[1])
}

func atoi(t *testing.T, value string) int {
	t.Helper()
	number, err := strconv.Atoi(value)
	if err != nil {
		t.Fatal(err)
	}
	return number
}

func cloneCounts(values map[string]int) map[string]int {
	cloned := map[string]int{}
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func assertNoPlaintextCanary(t *testing.T, name string, payload []byte) {
	t.Helper()
	if bytes.Contains(payload, []byte(plaintextCanary)) {
		t.Fatalf("%s leaked plaintext canary", name)
	}
}

func extractedPDFText(t *testing.T, payload []byte) (string, bool) {
	t.Helper()
	pdfToText, err := exec.LookPath("pdftotext")
	if err != nil {
		return "", false
	}
	path := filepath.Join(t.TempDir(), "secrets.pdf")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	extracted, err := exec.Command(pdfToText, path, "-").CombinedOutput()
	if err != nil {
		t.Fatalf("pdftotext: %v: %s", err, extracted)
	}
	return string(extracted), true
}

func TestCanonicalReportFixtureHasNoPlaintextCanary(t *testing.T) {
	t.Parallel()
	if strings.Contains(fmt.Sprintf("%#v", reportFixture()), plaintextCanary) {
		t.Fatal("canonical fixture retained the plaintext canary")
	}
}
