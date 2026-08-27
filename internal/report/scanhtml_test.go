package report

import (
	"bytes"
	"context"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/model"
)

func TestWriteTimestampedScanHTMLCreatesPrivateStandaloneArtifact(t *testing.T) {
	t.Chdir(t.TempDir())
	cvss := 8.1
	findings := []model.Finding{
		{
			CheckID:     "garga.tls.not_enabled",
			Title:       "Elasticsearch is exposed without TLS",
			Description: "The service was reached over HTTP.",
			Target:      model.Endpoint{Scheme: model.SchemeHTTP, Host: "192.0.2.10", Port: 9200},
			Product:     "elasticsearch",
			Version:     "8.19.19",
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceHigh,
			Remediation: "Enable TLS on the Elasticsearch HTTP interface.",
			Evidence:    []model.Evidence{{Code: "scheme_http", Summary: "HTTP scheme"}},
		},
		{
			CheckID:     "garga.exposure.anonymous_access",
			Title:       xssTitle,
			Description: "The anonymous user has the built-in superuser role.",
			Target:      model.Endpoint{Scheme: model.SchemeHTTP, Host: "192.0.2.10", Port: 9200},
			Product:     "elasticsearch",
			Severity:    model.SeverityCritical,
			Confidence:  model.ConfidenceHigh,
			Tags:        []string{"admin"},
			Evidence:    []model.Evidence{{Code: "class_admin", Summary: "superuser"}},
			Remediation: "Enable authentication.",
		},
		{
			CheckID:     "garga.vuln.cve-2014-3120",
			Title:       "Dynamic scripting remote code execution",
			Description: "Allows remote attackers to execute arbitrary MVEL expressions.",
			Target:      model.Endpoint{Scheme: model.SchemeHTTP, Host: "192.0.2.10", Port: 9200},
			Severity:    model.SeverityHigh,
			CVE:         []string{"CVE-2014-3120"},
			CVSS:        &cvss,
			Tags:        []string{"potential"},
			Remediation: "Upgrade Elasticsearch.",
			References:  []string{"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2014-3120"},
		},
	}
	path, err := WriteTimestampedScanHTML(findings, ProbeCoverage{Submitted: 1, Succeeded: 1}, "garga/test")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != mustWorkingDirectory(t) || !strings.HasPrefix(filepath.Base(path), "garga-scan-") {
		t.Fatalf("artifact path = %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact permissions = %o", info.Mode().Perm())
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	htmlReport := string(payload)
	for _, expected := range []string{
		"data:image/png;base64,",
		"garga logo",
		"Executive Summary",
		"Detailed Findings",
		"Why this appeared",
		"Operational and business impact",
		"What it costs if ignored",
		"How to fix it",
		"Prioritized Action Plan",
		"Affected Targets",
		"Security Intelligence Report",
		"--blue:#075985",
		"full-compromise class",
		"CVE-2014-3120",
		"Cuma Kurt",
		"https://www.linkedin.com/in/cuma-kurt-34414917/",
		"https://github.com/cumakurt",
		"LinkedIn",
		"GitHub",
	} {
		if !strings.Contains(htmlReport, expected) {
			t.Errorf("artifact missing %q", expected)
		}
	}
	if strings.Contains(htmlReport, xssTitle) {
		t.Fatal("HTML did not escape finding title")
	}
	if !strings.Contains(htmlReport, html.EscapeString(xssTitle)) {
		t.Fatal("escaped title missing from HTML")
	}
	if strings.Contains(strings.ToLower(htmlReport), "<script") {
		t.Fatal("HTML contains a script tag")
	}
}

func TestWithHTMLArtifactKeepsPrimaryFormatAndWritesFile(t *testing.T) {
	t.Chdir(t.TempDir())
	var stdout bytes.Buffer
	primary, err := New(FormatJSONL, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	var notice bytes.Buffer
	writer := WithHTMLArtifact(primary, &notice, "garga/test")
	finding := sampleFindings()[0]
	if err := writer.Write(context.Background(), finding); err != nil {
		t.Fatal(err)
	}
	writer.SetCoverage(ProbeCoverage{Submitted: 1, Succeeded: 1})
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"check_id":"garga.tls.not_enabled"`) {
		t.Fatalf("primary jsonl missing finding: %q", stdout.String())
	}
	if !strings.Contains(notice.String(), "HTML scan report written to") {
		t.Fatalf("notice = %q", notice.String())
	}
	matches, err := filepath.Glob("garga-scan-*.html")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("artifacts = %v", matches)
	}
}

func TestNarrativeExplainsAnonymousAdminCost(t *testing.T) {
	t.Parallel()
	finding := model.Finding{
		CheckID:    checkAnonymousAccess,
		Severity:   model.SeverityCritical,
		Confidence: model.ConfidenceHigh,
		Tags:       []string{"admin"},
		Evidence:   []model.Evidence{{Code: "class_admin"}},
	}
	narrative := narrativeFor(finding)
	if narrative.Category != "Authentication and authorization" {
		t.Fatalf("category = %q", narrative.Category)
	}
	if !strings.Contains(narrative.CostIfIgnored, "full-compromise") {
		t.Fatalf("cost = %q", narrative.CostIfIgnored)
	}
	if !strings.Contains(narrative.Cause, "Unauthenticated") {
		t.Fatalf("cause = %q", narrative.Cause)
	}
}

func mustWorkingDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return directory
}
