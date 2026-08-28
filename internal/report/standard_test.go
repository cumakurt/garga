package report

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/model"
)

func TestSARIFMapsFindingsToRulesResultsAndThreatProperties(t *testing.T) {
	t.Parallel()

	epss := 0.82
	priority := 9.4
	finding := sampleFindings()[0]
	finding.ID = ""
	finding.CVE = []string{"CVE-2021-44228"}
	finding.Description = "Affected runtime prerequisites were observed."
	finding.EPSS = &epss
	finding.PriorityScore = &priority
	finding.KnownExploited = true
	finding.Applicability = "applicable"
	finding.References = []string{"https://example.com/advisory"}

	var document sarifDocument
	output := renderFormat(t, FormatSARIF, []model.Finding{finding})
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatalf("json.Unmarshal(SARIF) error = %v", err)
	}
	if document.Version != "2.1.0" || len(document.Runs) != 1 {
		t.Fatalf("SARIF version/runs = %q/%d", document.Version, len(document.Runs))
	}
	run := document.Runs[0]
	if run.Tool.Driver.Name != "garga" || len(run.Tool.Driver.Rules) != 1 || len(run.Results) != 1 {
		t.Fatalf("SARIF driver/rules/results = %q/%d/%d", run.Tool.Driver.Name, len(run.Tool.Driver.Rules), len(run.Results))
	}
	result := run.Results[0]
	if result.RuleID != finding.CheckID || result.Level != "warning" {
		t.Fatalf("SARIF rule/level = %q/%q", result.RuleID, result.Level)
	}
	wantFingerprint := model.FindingID(finding.CheckID, finding.Target, finding.Resource)
	if result.Fingerprints["gargaFindingId/v1"] != wantFingerprint {
		t.Fatalf("SARIF fingerprint = %q, want %q", result.Fingerprints["gargaFindingId/v1"], wantFingerprint)
	}
	if result.Properties["knownExploited"] != true || result.Properties["applicability"] != "applicable" {
		t.Fatalf("SARIF threat properties = %#v", result.Properties)
	}
	if bytes.Contains(output, []byte(":null")) {
		t.Fatalf("SARIF contains null properties: %s", output)
	}
}

func TestVEXUsesExploitabilityStateAndStableComponentReference(t *testing.T) {
	t.Parallel()

	cvss := 10.0
	epss := 0.94
	finding := sampleFindings()[1]
	finding.CVE = []string{"CVE-2021-44228"}
	finding.CVSS = &cvss
	finding.EPSS = &epss
	finding.Version = "7.16.0"
	finding.Applicability = "applicable"
	finding.KnownExploited = true
	finding.References = []string{"https://example.com/b", "https://example.com/a", "https://example.com/a"}

	var document cyclonedxBOM
	output := renderFormat(t, FormatVEX, []model.Finding{finding})
	if err := json.Unmarshal(output, &document); err != nil {
		t.Fatalf("json.Unmarshal(VEX) error = %v", err)
	}
	if document.BOMFormat != "CycloneDX" || document.SpecVersion != "1.6" || document.Version != 1 {
		t.Fatalf("VEX header = %q/%q/%d", document.BOMFormat, document.SpecVersion, document.Version)
	}
	if len(document.Components) != 1 || len(document.Vulnerabilities) != 1 {
		t.Fatalf("VEX components/vulnerabilities = %d/%d", len(document.Components), len(document.Vulnerabilities))
	}
	vulnerability := document.Vulnerabilities[0]
	if vulnerability.ID != "CVE-2021-44228" || vulnerability.Analysis.State != "exploitable" {
		t.Fatalf("VEX vulnerability/state = %q/%q", vulnerability.ID, vulnerability.Analysis.State)
	}
	if vulnerability.Affects[0].Ref != document.Components[0].BOMRef {
		t.Fatalf("VEX affect ref = %q, component = %q", vulnerability.Affects[0].Ref, document.Components[0].BOMRef)
	}
	if len(vulnerability.Advisories) != 2 || vulnerability.Advisories[0].URL != "https://example.com/a" {
		t.Fatalf("VEX advisories = %#v", vulnerability.Advisories)
	}
	if !hasVEXProperty(vulnerability.Properties, "garga:known-exploited", "true") ||
		!hasVEXProperty(vulnerability.Properties, "garga:epss", "0.94") {
		t.Fatalf("VEX properties = %#v", vulnerability.Properties)
	}
}

func TestVEXDoesNotClaimUnverifiedFindingsAreExploitable(t *testing.T) {
	t.Parallel()

	finding := sampleFindings()[0]
	finding.Applicability = "potential"
	var document cyclonedxBOM
	if err := json.Unmarshal(renderFormat(t, FormatVEX, []model.Finding{finding}), &document); err != nil {
		t.Fatalf("json.Unmarshal(VEX) error = %v", err)
	}
	if got := document.Vulnerabilities[0].Analysis.State; got != "in_triage" {
		t.Fatalf("VEX analysis state = %q, want in_triage", got)
	}
}

func TestStandardWritersRejectWritesAfterClose(t *testing.T) {
	t.Parallel()

	for _, format := range []Format{FormatSARIF, FormatVEX} {
		writer, err := New(format, io.Discard)
		if err != nil {
			t.Fatalf("New(%s) error = %v", format, err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("Close(%s) error = %v", format, err)
		}
		if err := writer.Write(context.Background(), sampleFindings()[0]); err == nil {
			t.Fatalf("Write(%s) after close error = nil", format)
		}
	}
}

func TestStandardBufferEnforcesFindingLimit(t *testing.T) {
	t.Parallel()

	buffer := standardBuffer{findings: make([]model.Finding, maxStandardFindings)}
	err := buffer.add(sampleFindings()[0])
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("add() error = %v, want limit error", err)
	}
}

func hasVEXProperty(properties []cyclonedxProperty, name, value string) bool {
	for _, property := range properties {
		if property.Name == name && property.Value == value {
			return true
		}
	}
	return false
}
