package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	garga "github.com/cumakurt/garga"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/pdfdoc"
)

func writeScanPDF(output io.Writer, document scanHTMLDocument) error {
	doc := pdfdoc.New(
		"Test Report - Elasticsearch Security Assessment",
		document.Classification+" | "+document.ReportCode,
		"garga unauthenticated GET-only assessment",
	)
	doc.Logo(garga.LogoPNG())
	doc.Title("Test Report")
	doc.Subtitle(document.EngagementType)
	doc.KV("Report ID", document.ReportCode)
	doc.KV("Report version", document.ReportVersion)
	doc.KV("Generated", formatTimestamp(document.Generated))
	doc.KV("Assessor", document.DeveloperName)
	doc.KV("Classification", document.Classification)
	doc.KV("Assessment mode", "Unauthenticated, GET-only, non-destructive")
	doc.KV("Risk posture", fmt.Sprintf("%s  |  score %d / 100  |  %s", document.Posture, document.Score, document.HeadlineLabel))
	doc.PageBreak()

	doc.Section("1. Executive summary")
	doc.Para(document.Briefing)
	doc.KV("Findings", fmt.Sprintf("%d (%d exploitable-class)", document.Summary.Findings, document.Summary.Exploitable))
	doc.KV("Assets with findings", fmt.Sprintf("%d", document.Summary.Targets))
	doc.KV("CVE identifiers", fmt.Sprintf("%d", document.Summary.CVEs))
	doc.KV("Probes", fmt.Sprintf("%d submitted, %d succeeded, %d failed", document.Coverage.Submitted, document.Coverage.Succeeded, document.Coverage.Failed))
	doc.KV("Severity counts", fmt.Sprintf("critical %d, high %d, medium %d, low %d, info %d", document.Summary.Critical, document.Summary.High, document.Summary.Medium, document.Summary.Low, document.Summary.Info))

	doc.Section("2. Engagement overview")
	doc.Para("Identify unauthenticated exposure, transport weakness, missing authentication, public addressing, and potential Elasticsearch CVE matches on authorized HTTP targets.")
	doc.Para("This PDF is the engagement deliverable. Machine stdout (--format) is separate.")

	doc.Section("3. Scope")
	doc.Heading("In scope")
	doc.Bullets(document.ScopeIn)
	doc.Heading("Out of scope")
	doc.Bullets(document.ScopeOut)

	doc.Section("4. Rules of engagement")
	doc.Bullets(document.Rules)

	doc.Section("5. Methodology")
	for _, phase := range document.Phases {
		doc.Heading(phase.Name + " (" + phase.Standard + ")")
		doc.Para(phase.Description)
	}
	doc.Heading("Standards referenced")
	doc.Bullets(document.Standards)

	doc.Section("6. Risk rating methodology")
	rows := make([][]string, 0, len(document.RiskModel))
	for _, row := range document.RiskModel {
		rows = append(rows, []string{row.Severity, row.Definition, row.Response})
	}
	doc.Table([]string{"Severity", "Definition", "Response"}, rows)

	doc.Section("7. Summary of findings")
	if len(document.Categories) > 0 {
		catRows := make([][]string, 0, len(document.Categories))
		for _, row := range document.Categories {
			catRows = append(catRows, []string{row.Category, fmt.Sprintf("%d", row.Count), row.Highest})
		}
		doc.Table([]string{"Domain", "Count", "Highest"}, catRows)
	}
	register := make([][]string, 0, len(document.Findings))
	for index, finding := range document.Findings {
		status := finding.Status
		if finding.Exploitable {
			status = strings.TrimSpace(status + " / EXPLOITABLE")
		}
		register = append(register, []string{
			fmt.Sprintf("%d", index+1),
			finding.ReportID,
			finding.SeverityClass,
			finding.Title,
			finding.Target,
			dash(finding.CVSS),
			status,
		})
	}
	doc.SeverityTable([]string{"#", "ID", "Severity", "Title", "Asset", "CVSS", "Status"}, register)

	doc.Section("8. Key findings for management")
	if len(document.TopRisks) == 0 {
		doc.Para("No scored security findings were emitted for the endpoints that were probed.")
	}
	for _, finding := range document.TopRisks {
		flags := scanPDFFlags(finding)
		if finding.Exploitable {
			flags = append(flags, "EXPLOITABLE")
		}
		doc.FindingCard(findingNumber(finding.ReportID), finding.ReportID, finding.SeverityClass, finding.Title, flags, compactPDFFields([][]string{
			{"Asset", finding.Target},
			{"CVE / CVSS", joinPDFValues(finding.CVE, finding.CVSS)},
			{"Impact", finding.Impact},
		}))
	}

	doc.Section("9. Technical findings")
	if len(document.FindingGroups) == 0 {
		doc.Para("No findings were produced.")
	}
	for _, group := range document.FindingGroups {
		doc.GroupBanner(group.Class, fmt.Sprintf("%s  ·  %d finding(s)", group.Class, group.Count))
		for _, finding := range group.Findings {
			writeScanPDFFinding(doc, finding)
		}
	}

	doc.Section("10. Attack scenarios")
	if len(document.Scenarios) == 0 {
		doc.Para("No attack path was inferred beyond individual findings.")
	}
	for _, scenario := range document.Scenarios {
		doc.Badge(scenario.Class, scenario.Title)
		doc.Para(scenario.Narrative)
		if len(scenario.Findings) > 0 {
			doc.Para("Supporting findings: " + strings.Join(scenario.Findings, ", "))
		}
	}

	doc.Section("11. Remediation roadmap")
	writeScanPDFActions(doc, document.Actions)

	doc.Section("12. Positive observations")
	doc.Bullets(document.Strengths)

	doc.Section("13. Coverage, limitations, and residual testing gaps")
	doc.KV("Duration", formatScanDuration(document.Coverage.Duration))
	doc.KV("Scanner", firstNonEmpty(document.ScannerVersion, "garga"))
	doc.Bullets(document.Limitations)

	doc.Section("Appendix A - Asset inventory")
	assets := make([][]string, 0, len(document.Targets))
	for _, target := range document.Targets {
		assets = append(assets, []string{target.Target, dash(target.Product), dash(target.Version), fmt.Sprintf("%d", target.Findings), dash(target.Highest), fmt.Sprintf("%d", target.Exploitable)})
	}
	doc.Table([]string{"Target", "Product", "Version", "Findings", "Highest", "Expl."}, assets)

	doc.Section("Appendix B - CVE catalog")
	if len(document.CVEs) == 0 {
		doc.Para("No CVE identifiers were matched.")
	} else {
		cves := make([][]string, 0, len(document.CVEs))
		for _, item := range document.CVEs {
			cves = append(cves, []string{item.ID, item.Title, dash(item.CVSS), item.Targets, item.ReportIDs})
		}
		doc.Table([]string{"CVE", "Title", "CVSS", "Assets", "Findings"}, cves)
	}

	doc.Section("Appendix C - Glossary")
	terms := make([][]string, 0, len(document.Glossary))
	for _, term := range document.Glossary {
		terms = append(terms, []string{term.Term, term.Meaning})
	}
	doc.Table([]string{"Term", "Meaning"}, terms)

	doc.Section("Disclaimer")
	doc.Bullets(document.Disclaimer)
	doc.Para("Assessor " + document.DeveloperName + "  |  " + document.DeveloperLinkedInURL + "  |  " + document.DeveloperGitHubURL)
	return doc.Write(output)
}

func writeScanPDFFinding(doc *pdfdoc.Doc, finding scanHTMLFinding) {
	flags := scanPDFFlags(finding)
	if finding.Exploitable {
		flags = append(flags, "EXPLOITABLE")
	}
	asset := finding.Target
	if finding.Product != "" {
		asset += "  ·  " + finding.Product
	}
	if finding.Version != "" {
		asset += " " + finding.Version
	}
	fields := [][]string{
		{"Status", finding.Status},
		{"Check", finding.CheckID},
		{"Asset", asset},
		{"Category", strings.TrimSpace(finding.Category + "  " + finding.Resource)},
		{"Vector", finding.Vector},
		{"Likelihood", finding.Likelihood},
		{"Confidence", finding.Confidence},
		{"CVSS / CVE", joinPDFValues(finding.CVSS, finding.CVE)},
		{"EPSS probability", finding.EPSS},
		{"EPSS percentile", finding.EPSSPercentile},
		{"Priority score", finding.PriorityScore},
		{"Applicability", finding.Applicability},
		{"Known exploited", scanPDFKnownExploited(finding)},
		{"Threat data updated", finding.ThreatUpdated},
		{"OWASP", finding.OWASP},
		{"CWE", finding.CWE},
	}
	if finding.Description != "" {
		fields = append(fields, []string{"Description", finding.Description})
	}
	fields = append(fields,
		[]string{"Technical details", finding.Cause},
		[]string{"Impact", finding.Impact},
		[]string{"Business impact", finding.CostIfIgnored},
		[]string{"Recommendation", finding.Fix},
		[]string{"Residual risk", finding.ResidualRisk},
		[]string{"Reproduction", finding.Reproduction},
	)
	for _, card := range finding.EvidenceCards {
		fields = append(fields, []string{"Evidence", card.Code + " - " + card.Summary})
	}
	if len(finding.References) > 0 {
		fields = append(fields, []string{"References", strings.Join(finding.References, "  |  ")})
	}
	if finding.Exploitable && finding.ExploitableNote != "" {
		fields = append(fields, []string{"Exploitable note", finding.ExploitableNote})
	}
	doc.FindingCard(findingNumber(finding.ReportID), finding.ReportID, finding.SeverityClass, finding.Title, flags, compactPDFFields(fields))
}

func scanPDFFlags(finding scanHTMLFinding) []string {
	flags := make([]string, 0, 2)
	if finding.Applicability != "" {
		flags = append(flags, strings.ToUpper(finding.Applicability))
	}
	if finding.KnownExploited {
		flags = append(flags, "CISA KEV")
	}
	return flags
}

func scanPDFKnownExploited(finding scanHTMLFinding) string {
	if finding.KnownExploited {
		return "Yes - CISA Known Exploited Vulnerabilities catalog"
	}
	if finding.CVE != "" {
		return "No"
	}
	return ""
}

func compactPDFFields(fields [][]string) [][]string {
	out := make([][]string, 0, len(fields))
	for _, field := range fields {
		if len(field) < 2 || strings.TrimSpace(field[1]) == "" || strings.TrimSpace(field[1]) == "-" {
			continue
		}
		out = append(out, field)
	}
	return out
}

func findingNumber(reportID string) int {
	var number int
	_, _ = fmt.Sscanf(reportID, "F-%d", &number)
	if number <= 0 {
		return 1
	}
	return number
}

func writeScanPDFActions(doc *pdfdoc.Doc, actions scanHTMLActions) {
	write := func(title string, items []string) {
		doc.Heading(title)
		if len(items) == 0 {
			doc.Para("None.")
			return
		}
		doc.Bullets(items)
	}
	write("P0 Immediate", actions.Immediate)
	write("P1 Urgent", actions.Urgent)
	write("P2 Planned", actions.Planned)
	write("P3 Optimization", actions.Optimization)
}

func dash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func joinPDFValues(values ...string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || value == "-" {
			continue
		}
		parts = append(parts, value)
	}
	return strings.Join(parts, "  ")
}

func WriteTimestampedScanPDF(findings []model.Finding, coverage ProbeCoverage, scannerVersion string) (path string, err error) {
	generated := time.Now().UTC()
	prefix := ".garga-scan-" + generated.Format("20060102T150405.000Z") + "-"
	document := buildScanHTMLDocument(findings, coverage, scannerVersion, generated)
	return pdfdoc.WriteCWD(prefix, ".pdf", "scan PDF", func(output io.Writer) error {
		return writeScanPDF(output, document)
	})
}
