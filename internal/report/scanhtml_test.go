package report

import (
	"bytes"
	"context"
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		"Executive summary",
		"Document control",
		"Disclaimer, authorization, and confidentiality",
		"Engagement overview",
		"Rules of engagement",
		"Methodology",
		"Risk rating methodology",
		"Summary of findings",
		"Key findings for management",
		"Technical findings",
		"Attack scenarios",
		"Remediation roadmap",
		"Positive observations",
		"Coverage, limitations, and residual testing gaps",
		"Appendix A — Asset inventory",
		"Appendix B — CVE catalog",
		"Appendix C — Glossary",
		"Penetration Test Report",
		"Confidential",
		"PTES",
		"NIST SP 800-115",
		"OWASP",
		"CREST",
		"F-001",
		"Vulnerability description",
		"Technical details",
		"Business impact if ignored",
		"Recommendation",
		"Evidence / proof of observation",
		"--blue:#075985",
		"full-compromise class",
		"CVE-2014-3120",
		"Cuma Kurt",
		"https://www.linkedin.com/in/cuma-kurt-34414917/",
		"https://github.com/cumakurt",
		"LinkedIn",
		"GitHub",
		"Critical findings",
		`class="score CRITICAL"`,
		`class="status-cell CRITICAL"`,
		"Risk score",
		`class="evidence-card"`,
		`class="evidence-code"`,
		"scheme_http",
		"class_admin",
		"observed_target",
		"advisory_cve-2014-3120",
		"cvss_score",
		"The finding was produced for",
		"OWASP A07:2021",
		"CWE-306",
		"GARGA-PT-",
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
	if got := strings.Count(htmlReport, "Evidence / proof of observation"); got != 3 {
		t.Fatalf("evidence panels = %d, want 3", got)
	}
	wantCards := 0
	for _, finding := range findings {
		wantCards += len(visualEvidence(finding))
	}
	if got := strings.Count(htmlReport, `class="evidence-card"`); got < wantCards {
		t.Fatalf("evidence cards = %d, want at least %d", got, wantCards)
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

func TestWithPDFArtifactKeepsPrimaryFormatAndWritesFile(t *testing.T) {
	t.Chdir(t.TempDir())
	var stdout bytes.Buffer
	primary, err := New(FormatJSONL, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	var notice bytes.Buffer
	writer := WithArtifacts(primary, &notice, "garga/test", ArtifactOptions{PDF: true})
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
	if !strings.Contains(notice.String(), "PDF scan report written to") {
		t.Fatalf("notice = %q", notice.String())
	}
	matches, err := filepath.Glob("garga-scan-*.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("artifacts = %v", matches)
	}
	payload, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(payload, []byte("%PDF")) || !bytes.Contains(payload, []byte("1. Executive summary")) || !bytes.Contains(payload, []byte("1. F-")) || !bytes.Contains(payload, []byte("Field")) {
		t.Fatalf("PDF artifact is incomplete: %d bytes", len(payload))
	}
}

func TestWriteTimestampedScanPDFIncludesExploitableFindings(t *testing.T) {
	t.Chdir(t.TempDir())
	cvss := 10.0
	findings := []model.Finding{
		{
			CheckID:     "garga.exposure.anonymous_access",
			Title:       "Elasticsearch likely allows unauthenticated cluster administration",
			Description: "Security APIs are unavailable and cluster APIs responded without credentials.",
			Target:      model.Endpoint{Scheme: model.SchemeHTTP, Host: "192.0.2.10", Port: 9200},
			Product:     "elasticsearch",
			Version:     "7.10.0",
			Severity:    model.SeverityCritical,
			Confidence:  model.ConfidenceMedium,
			Tags:        []string{"exposure", "authentication", "admin", "inferred", "exploitable"},
			Evidence:    []model.Evidence{{Code: "class_admin_inferred", Summary: "Admin access is inferred from missing security APIs plus unauthenticated cluster APIs."}},
			Remediation: "Enable Elasticsearch security features and require authentication for HTTP APIs.",
		},
		{
			CheckID:     "garga.vuln.cve-2021-44228",
			Title:       "Apache Log4j2 message lookup vulnerabilities in Elasticsearch",
			Description: "Elasticsearch versions containing affected Log4j2 components can expose information and, on older JDK and Elasticsearch combinations, permit remote code execution.",
			Target:      model.Endpoint{Scheme: model.SchemeHTTP, Host: "192.0.2.10", Port: 9200},
			Product:     "elasticsearch",
			Version:     "7.10.0",
			Severity:    model.SeverityCritical,
			Confidence:  model.ConfidenceLow,
			CVE:         []string{"CVE-2021-44228"},
			CVSS:        &cvss,
			Tags:        []string{"potential"},
			References:  []string{"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
			Remediation: "Upgrade to a vendor-fixed Elasticsearch release.",
		},
		{
			CheckID:     "garga.tls.not_enabled",
			Title:       "Elasticsearch is exposed without TLS",
			Description: "The service was reached over HTTP.",
			Target:      model.Endpoint{Scheme: model.SchemeHTTP, Host: "192.0.2.10", Port: 9200},
			Product:     "elasticsearch",
			Version:     "7.10.0",
			Severity:    model.SeverityHigh,
			Confidence:  model.ConfidenceHigh,
			Evidence:    []model.Evidence{{Code: "scheme_http", Summary: "The Elasticsearch endpoint used the HTTP scheme."}},
			Remediation: "Enable TLS on the Elasticsearch HTTP interface.",
		},
	}
	path, err := WriteTimestampedScanPDF(findings, ProbeCoverage{Submitted: 6, Succeeded: 6}, "garga/test")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(payload, []byte("%PDF")) {
		t.Fatalf("artifact is not a PDF: %q", path)
	}
	body := string(payload)
	for _, needle := range []string{
		"EXPLOITABLE",
		"unauthenticated cluster administration",
		"CVE-2021-44228",
		"2 exploitable-class",
		"garga.exposure.anonymous_access",
		"garga.vuln.cve-2021-44228",
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("PDF missing %q", needle)
		}
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

func TestPentestReportGroupsFindingsAndMapsWeaknesses(t *testing.T) {
	t.Parallel()
	findings := []scanHTMLFinding{
		{CheckID: checkAnonymousAccess, Title: "anon", Target: "http://192.0.2.10:9200/", SeverityClass: "CRITICAL", Category: "Authentication and authorization", Confidence: "high", Exploitable: true},
		{CheckID: "garga.tls.not_enabled", Title: "tls", Target: "http://192.0.2.10:9200/", SeverityClass: "HIGH", Category: "Transport security", Confidence: "high"},
		{CheckID: "garga.vuln.cve-2014-3120", Title: "rce", Target: "http://192.0.2.10:9200/", SeverityClass: "HIGH", Category: "Vulnerability", CVE: "CVE-2014-3120", CVSS: "8.1"},
	}
	findings = assignReportIDs(findings)
	if findings[0].ReportID != "F-001" || findings[0].OWASP == "" || findings[0].CWE == "" {
		t.Fatalf("enrichment = %#v", findings[0])
	}
	groups := groupFindingsBySeverity(findings)
	if len(groups) != 2 || groups[0].Class != "CRITICAL" || groups[1].Class != "HIGH" {
		t.Fatalf("groups = %#v", groups)
	}
	scenarios := deriveAttackScenarios(findings)
	if len(scenarios) == 0 {
		t.Fatal("expected an attack scenario from anonymous plus missing TLS")
	}
	cves := pentestCVEAppendix(findings)
	if len(cves) != 1 || cves[0].ID != "CVE-2014-3120" {
		t.Fatalf("cves = %#v", cves)
	}
}

func TestScanHeadlineShowsCriticalCountInsteadOfCollapsedScore(t *testing.T) {
	t.Parallel()
	summary := scanHTMLSummary{Findings: 27, Critical: 1, High: 4, Medium: 22, Exploitable: 3, CVEs: 24}
	count, label, class := scanHeadline(summary)
	if count != 1 || class != "CRITICAL" || label != "Critical findings" {
		t.Fatalf("headline = %d %q %q", count, label, class)
	}
	score, posture := scanRiskScore(summary)
	if score <= 0 {
		t.Fatalf("risk score collapsed to %d", score)
	}
	if posture != "Critical" {
		t.Fatalf("posture = %q", posture)
	}
	if postureClass(posture) != "CRITICAL" {
		t.Fatalf("posture class = %q", postureClass(posture))
	}
}

func TestScanFindingViewIncludesThreatPrioritization(t *testing.T) {
	t.Parallel()

	epss := 0.99999
	percentile := 1.0
	priority := 10.0
	updated := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	view := scanFindingView(model.Finding{
		CheckID: "garga.vuln.cve-2021-44228", CVE: []string{"CVE-2021-44228"}, Severity: model.SeverityCritical,
		EPSS: &epss, EPSSPercentile: &percentile, PriorityScore: &priority, KnownExploited: true,
		Applicability: "applicable", ThreatUpdated: &updated,
	})
	if view.EPSS != "99.999%" || view.EPSSPercentile != "100.000%" || view.PriorityScore != "10.00 / 10" {
		t.Fatalf("threat scores = %#v", view)
	}
	if !view.KnownExploited || view.Applicability != "applicable" || view.ThreatUpdated != "2026-08-27" {
		t.Fatalf("threat state = %#v", view)
	}
	flags := scanPDFFlags(view)
	if strings.Join(flags, ",") != "APPLICABLE,CISA KEV" {
		t.Fatalf("PDF flags = %#v", flags)
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
