package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	garga "github.com/cumakurt/garga"
	"github.com/cumakurt/garga/internal/model"
)

type scanHTMLDocument struct {
	LogoBase64           string
	Generated            time.Time
	ScannerVersion       string
	Briefing             string
	Posture              string
	Score                int
	Coverage             ProbeCoverage
	Summary              scanHTMLSummary
	Targets              []scanHTMLTarget
	TopRisks             []scanHTMLFinding
	Findings             []scanHTMLFinding
	Actions              scanHTMLActions
	HeadlineCount        int
	HeadlineLabel        string
	HeadlineClass        string
	DeveloperName        string
	DeveloperGitHubURL   string
	DeveloperLinkedInURL string
}

type ProbeCoverage struct {
	Submitted uint64
	Succeeded uint64
	Failed    uint64
	Duration  time.Duration
}

type scanHTMLSummary struct {
	Findings    int
	Exploitable int
	Targets     int
	CVEs        int
	Critical    int
	High        int
	Medium      int
	Low         int
	Info        int
}

type scanHTMLTarget struct {
	Target      string
	Product     string
	Version     string
	Findings    int
	Highest     string
	Exploitable int
}

type scanHTMLFinding struct {
	ID              string
	CheckID         string
	Title           string
	Target          string
	Product         string
	Version         string
	Severity        string
	SeverityClass   string
	Confidence      string
	Category        string
	Resource        string
	Exploitable     bool
	ExploitableNote string
	CVE             string
	CVSS            string
	Tags            string
	Description     string
	Cause           string
	Impact          string
	CostIfIgnored   string
	Fix             string
	ResidualRisk    string
	EvidenceCards   []evidenceCard
	References      []string
}

type scanHTMLActions struct {
	Immediate    []string
	Urgent       []string
	Planned      []string
	Optimization []string
}

var (
	scanHTMLOnce     sync.Once
	scanHTMLTemplate *template.Template
	scanHTMLParseErr error
)

func writeScanHTML(output io.Writer, document scanHTMLDocument) error {
	scanHTMLOnce.Do(func() {
		scanHTMLTemplate, scanHTMLParseErr = template.New("scan-report").Funcs(template.FuncMap{
			"duration":     formatScanDuration,
			"timestamp":    formatTimestamp,
			"postureClass": postureClass,
		}).Parse(scanHTMLSource)
	})
	if scanHTMLParseErr != nil {
		return fmt.Errorf("prepare scan HTML report: %w", scanHTMLParseErr)
	}
	if document.Generated.IsZero() {
		document.Generated = time.Now().UTC()
	}
	if document.LogoBase64 == "" {
		document.LogoBase64 = garga.LogoPNGBase64()
	}
	if err := scanHTMLTemplate.Execute(output, document); err != nil {
		return fmt.Errorf("write scan HTML report: %w", err)
	}
	return nil
}

func buildScanHTMLDocument(findings []model.Finding, coverage ProbeCoverage, scannerVersion string, generated time.Time) scanHTMLDocument {
	views := make([]scanHTMLFinding, 0, len(findings))
	for _, finding := range findings {
		views = append(views, scanFindingView(prepared(finding)))
	}
	sort.SliceStable(views, func(left, right int) bool {
		if views[left].Exploitable != views[right].Exploitable {
			return views[left].Exploitable
		}
		if rank := severityRank(model.Severity(strings.ToLower(views[left].Severity))) - severityRank(model.Severity(strings.ToLower(views[right].Severity))); rank != 0 {
			return rank > 0
		}
		if views[left].CheckID != views[right].CheckID {
			return views[left].CheckID < views[right].CheckID
		}
		return views[left].Target < views[right].Target
	})
	summary := summarizeScanFindings(views)
	score, posture := scanRiskScore(summary)
	headlineCount, headlineLabel, headlineClass := scanHeadline(summary)
	top := views
	if len(top) > 6 {
		top = top[:6]
	}
	return scanHTMLDocument{
		LogoBase64:           garga.LogoPNGBase64(),
		Generated:            generated.UTC(),
		ScannerVersion:       scannerVersion,
		Briefing:             executiveBriefing(summary, coverage),
		Posture:              posture,
		Score:                score,
		Coverage:             coverage,
		Summary:              summary,
		Targets:              scanTargetInventory(views),
		TopRisks:             top,
		Findings:             views,
		Actions:              scanActions(views),
		HeadlineCount:        headlineCount,
		HeadlineLabel:        headlineLabel,
		HeadlineClass:        headlineClass,
		DeveloperName:        garga.DeveloperName,
		DeveloperGitHubURL:   garga.DeveloperGitHubURL,
		DeveloperLinkedInURL: garga.DeveloperLinkedInURL,
	}
}

func scanFindingView(finding model.Finding) scanHTMLFinding {
	narrative := narrativeFor(finding)
	cvss := ""
	if finding.CVSS != nil {
		cvss = fmt.Sprintf("%.1f", *finding.CVSS)
	}
	return scanHTMLFinding{
		ID:              finding.ID,
		CheckID:         finding.CheckID,
		Title:           finding.Title,
		Target:          targetDisplay(finding.Target),
		Product:         finding.Product,
		Version:         finding.Version,
		Severity:        string(finding.Severity),
		SeverityClass:   strings.ToUpper(string(finding.Severity)),
		Confidence:      string(finding.Confidence),
		Category:        narrative.Category,
		Resource:        finding.Resource,
		Exploitable:     exploitable(finding),
		ExploitableNote: exploitableNote(finding),
		CVE:             strings.Join(finding.CVE, ", "),
		CVSS:            cvss,
		Tags:            strings.Join(finding.Tags, ", "),
		Description:     finding.Description,
		Cause:           narrative.Cause,
		Impact:          narrative.Impact,
		CostIfIgnored:   narrative.CostIfIgnored,
		Fix:             narrative.Fix,
		ResidualRisk:    narrative.ResidualRisk,
		EvidenceCards:   visualEvidence(finding),
		References:      append([]string(nil), finding.References...),
	}
}

func summarizeScanFindings(findings []scanHTMLFinding) scanHTMLSummary {
	summary := scanHTMLSummary{Findings: len(findings)}
	targets := map[string]struct{}{}
	cves := map[string]struct{}{}
	for _, finding := range findings {
		targets[finding.Target] = struct{}{}
		if finding.Exploitable {
			summary.Exploitable++
		}
		for _, cve := range strings.Split(finding.CVE, ", ") {
			if cve = strings.TrimSpace(cve); cve != "" {
				cves[cve] = struct{}{}
			}
		}
		switch model.Severity(strings.ToLower(finding.Severity)) {
		case model.SeverityCritical:
			summary.Critical++
		case model.SeverityHigh:
			summary.High++
		case model.SeverityMedium:
			summary.Medium++
		case model.SeverityLow:
			summary.Low++
		default:
			summary.Info++
		}
	}
	summary.Targets = len(targets)
	summary.CVEs = len(cves)
	return summary
}

func scanRiskScore(summary scanHTMLSummary) (int, string) {
	if summary.Findings == 0 {
		return 100, "Clear"
	}
	score := 100 - min(45, summary.Critical*25) - min(30, summary.High*8) - min(18, summary.Medium*2) - min(8, summary.Low) - min(12, summary.Exploitable*4)
	if score < 0 {
		score = 0
	}
	switch {
	case summary.Critical > 0 || summary.Exploitable > 0:
		return score, "Critical"
	case summary.High > 0:
		return score, "Poor"
	case summary.Medium > 0:
		return score, "Fair"
	case summary.Low > 0:
		return score, "Good"
	default:
		return score, "Strong"
	}
}

func scanHeadline(summary scanHTMLSummary) (int, string, string) {
	switch {
	case summary.Critical > 0:
		return summary.Critical, "Critical findings", "CRITICAL"
	case summary.High > 0:
		return summary.High, "High findings", "HIGH"
	case summary.Medium > 0:
		return summary.Medium, "Medium findings", "MEDIUM"
	case summary.Low > 0:
		return summary.Low, "Low findings", "LOW"
	case summary.Info > 0:
		return summary.Info, "Informational findings", "INFO"
	default:
		return 0, "No findings", "OK"
	}
}

func postureClass(posture string) string {
	switch posture {
	case "Critical":
		return "CRITICAL"
	case "Poor":
		return "HIGH"
	case "Fair":
		return "MEDIUM"
	case "Good":
		return "LOW"
	default:
		return "OK"
	}
}

func executiveBriefing(summary scanHTMLSummary, coverage ProbeCoverage) string {
	if summary.Findings == 0 {
		if coverage.Failed > 0 {
			return "The scan finished without emitting exposure or signature findings, but some probes failed operationally. Absence of a finding is only meaningful for endpoints that were successfully fingerprinted. Re-run failed targets and do not treat this file as a clean bill of health for the whole input set."
		}
		if coverage.Succeeded == 0 {
			return "No endpoints were successfully probed. This artifact does not demonstrate that Elasticsearch is safe; it only records that the run produced no findings."
		}
		return "No exposure or signature findings were emitted for the Elasticsearch endpoints that were successfully probed. That is not a warranty: garga is GET-only, does not authenticate, and does not prove that a later authenticated or internal path is safe."
	}
	parts := []string{
		fmt.Sprintf("This GET-only security scan recorded %d finding(s) across %d target(s).", summary.Findings, summary.Targets),
	}
	if summary.Exploitable > 0 {
		parts = append(parts, fmt.Sprintf("%d finding(s) are marked EXPLOITABLE: unauthenticated read/write/admin access or a remote-compromise advisory class. The mark is listing emphasis, not confirmed exploitation.", summary.Exploitable))
	}
	if summary.Critical > 0 {
		parts = append(parts, "Critical findings indicate cluster takeover or equivalent impact if the HTTP port remains reachable. Contain network exposure and enable authentication before debating patch windows.")
	} else if summary.High > 0 {
		parts = append(parts, "High findings indicate material confidentiality, integrity, or availability risk. Treat them as a near-term hardening backlog, not informational noise.")
	}
	if summary.CVEs > 0 {
		parts = append(parts, fmt.Sprintf("%d distinct CVE identifier(s) matched advertised versions. Signature hits stay potential until patch status and attack preconditions are confirmed.", summary.CVEs))
	}
	parts = append(parts, "Each finding below states why it appeared, what it costs if ignored, how to fix it, and what residual uncertainty remains. garga did not send credentials, writes, or exploit payloads.")
	return strings.Join(parts, " ")
}

func scanTargetInventory(findings []scanHTMLFinding) []scanHTMLTarget {
	index := map[string]int{}
	var targets []scanHTMLTarget
	for _, finding := range findings {
		position, ok := index[finding.Target]
		if !ok {
			index[finding.Target] = len(targets)
			targets = append(targets, scanHTMLTarget{
				Target:  finding.Target,
				Product: finding.Product,
				Version: finding.Version,
			})
			position = len(targets) - 1
		}
		item := targets[position]
		item.Findings++
		if finding.Exploitable {
			item.Exploitable++
		}
		if finding.Product != "" {
			item.Product = finding.Product
		}
		if finding.Version != "" {
			item.Version = finding.Version
		}
		if severityRank(model.Severity(strings.ToLower(finding.SeverityClass))) > severityRank(model.Severity(strings.ToLower(item.Highest))) {
			item.Highest = finding.SeverityClass
		}
		targets[position] = item
	}
	sort.SliceStable(targets, func(left, right int) bool {
		if rank := severityRank(model.Severity(strings.ToLower(targets[left].Highest))) - severityRank(model.Severity(strings.ToLower(targets[right].Highest))); rank != 0 {
			return rank > 0
		}
		return targets[left].Target < targets[right].Target
	})
	return targets
}

func scanActions(findings []scanHTMLFinding) scanHTMLActions {
	seen := [4]map[string]struct{}{{}, {}, {}, {}}
	var actions scanHTMLActions
	for _, finding := range findings {
		text := strings.TrimSpace(finding.Fix)
		if text == "" {
			continue
		}
		if finding.Target != "" {
			text = finding.Target + " — " + text
		}
		bucket := 3
		switch model.Severity(strings.ToLower(finding.Severity)) {
		case model.SeverityCritical:
			bucket = 0
		case model.SeverityHigh:
			bucket = 1
		case model.SeverityMedium:
			bucket = 2
		}
		if _, exists := seen[bucket][text]; exists {
			continue
		}
		seen[bucket][text] = struct{}{}
		switch bucket {
		case 0:
			actions.Immediate = append(actions.Immediate, text)
		case 1:
			actions.Urgent = append(actions.Urgent, text)
		case 2:
			actions.Planned = append(actions.Planned, text)
		default:
			actions.Optimization = append(actions.Optimization, text)
		}
	}
	return actions
}

func formatScanDuration(duration time.Duration) string {
	if duration <= 0 {
		return "Not available"
	}
	if duration < time.Second {
		return duration.Round(time.Millisecond).String()
	}
	return duration.Round(time.Millisecond).String()
}

func formatTimestamp(value time.Time) string {
	if value.IsZero() {
		return "Not available"
	}
	return value.UTC().Format("2006-01-02 15:04:05 MST")
}

const scanHTMLSource = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>garga Elasticsearch Security Scan &amp; Assessment</title>
<style>
:root{--blue:#075985;--blue-2:#0b6ea8;--teal:#0f766e;--ink:#172033;--muted:#5f6b7a;--line:#d9e2ec;--panel:#fff;--canvas:#f4f7fa;--critical:#b42318;--critical-bg:#fff0ee;--high:#c2410c;--high-bg:#fff4e8;--medium:#a16207;--medium-bg:#fff9db;--low:#0369a1;--low-bg:#edf8ff;--info:#475569;--info-bg:#f1f5f9;--ok:#15803d;--ok-bg:#edfaf1;--shadow:0 10px 30px rgba(15,45,70,.08)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}.page{max-width:1440px;margin:0 auto;padding:30px}.masthead{background:linear-gradient(120deg,#fff 0%,#f7fbfe 70%,#edf7fb 100%);border:1px solid var(--line);border-top:6px solid var(--blue-2);border-radius:14px;box-shadow:var(--shadow);padding:24px 28px;display:flex;gap:28px;justify-content:space-between;align-items:center}.brand{display:flex;gap:20px;align-items:center}.brand img{width:176px;height:88px;object-fit:contain}.eyebrow{color:var(--blue-2);font-weight:800;letter-spacing:.12em;text-transform:uppercase;font-size:11px}.brand h1{font-size:27px;line-height:1.15;margin:5px 0 8px}.subtitle{color:var(--muted);max-width:760px}.score{min-width:200px;text-align:center;padding:18px 22px;border-radius:14px;border:1px solid var(--line);background:#fff}.score-value{font-size:48px;font-weight:850;line-height:1;color:var(--blue)}.score-label{font-weight:750;margin-top:7px}.score small{color:var(--muted);display:block;margin-top:6px}.score.CRITICAL{background:var(--critical-bg);border-color:#f0c2bd}.score.HIGH{background:var(--high-bg);border-color:#f3d0b5}.score.MEDIUM{background:var(--medium-bg);border-color:#ead889}.score.LOW{background:var(--low-bg);border-color:#bdd9ee}.score.INFO{background:var(--info-bg);border-color:#d5dde6}.score.OK{background:var(--ok-bg);border-color:#c6e6cf}.score.CRITICAL .score-value,.score.CRITICAL .score-label{color:var(--critical)}.score.HIGH .score-value,.score.HIGH .score-label{color:var(--high)}.score.MEDIUM .score-value,.score.MEDIUM .score-label{color:var(--medium)}.score.LOW .score-value,.score.LOW .score-label{color:var(--low)}.score.INFO .score-value,.score.INFO .score-label{color:var(--info)}.score.OK .score-value,.score.OK .score-label{color:var(--ok)}.nav{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}.nav a{background:#fff;border:1px solid var(--line);border-radius:999px;padding:7px 12px;font-size:12px;font-weight:700}.section{margin-top:22px}.section-head{display:flex;align-items:end;justify-content:space-between;gap:16px;margin:0 0 10px}.section h2{font-size:19px;margin:0}.section-note{color:var(--muted);font-size:12px}.grid{display:grid;gap:14px}.grid-4{grid-template-columns:repeat(4,minmax(0,1fr))}.grid-3{grid-template-columns:repeat(3,minmax(0,1fr))}.grid-2{grid-template-columns:repeat(2,minmax(0,1fr))}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 4px 16px rgba(15,45,70,.045);padding:17px}.card.metric{border-left:5px solid var(--line)}.card.metric.CRITICAL,.status-cell.CRITICAL{background:var(--critical-bg);border-color:#f0c2bd}.card.metric.HIGH,.status-cell.HIGH{background:var(--high-bg);border-color:#f3d0b5}.card.metric.MEDIUM,.status-cell.MEDIUM{background:var(--medium-bg);border-color:#ead889}.card.metric.LOW,.status-cell.LOW{background:var(--low-bg);border-color:#bdd9ee}.card.metric.INFO,.status-cell.INFO{background:var(--info-bg);border-color:#d5dde6}.card.metric.OK,.status-cell.OK{background:var(--ok-bg);border-color:#c6e6cf}.card.metric.CRITICAL,.status-cell.CRITICAL{border-left:5px solid var(--critical)}.card.metric.HIGH,.status-cell.HIGH{border-left:5px solid var(--high)}.card.metric.MEDIUM,.status-cell.MEDIUM{border-left:5px solid var(--medium)}.card.metric.LOW,.status-cell.LOW{border-left:5px solid var(--low)}.card.metric.INFO,.status-cell.INFO{border-left:5px solid var(--info)}.card.metric.OK,.status-cell.OK{border-left:5px solid var(--ok)}.card.metric.CRITICAL .metric-value,.status-cell.CRITICAL strong{color:var(--critical)}.card.metric.HIGH .metric-value,.status-cell.HIGH strong{color:var(--high)}.card.metric.MEDIUM .metric-value,.status-cell.MEDIUM strong{color:var(--medium)}.card.metric.LOW .metric-value,.status-cell.LOW strong{color:var(--low)}.card.metric.INFO .metric-value,.status-cell.INFO strong{color:var(--info)}.card.metric.OK .metric-value,.status-cell.OK strong{color:var(--ok)}.metric-label{color:var(--muted);font-size:11px;font-weight:750;letter-spacing:.06em;text-transform:uppercase}.metric-value{font-size:23px;font-weight:800;margin-top:5px;overflow-wrap:anywhere}.metric-detail{font-size:12px;color:var(--muted);margin-top:3px}.status-row{display:grid;grid-template-columns:1.5fr repeat(5,1fr);gap:10px}.status-cell{border:1px solid var(--line);border-radius:10px;background:#fff;padding:13px}.status-cell strong{display:block;font-size:21px}.status-cell span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em}.risk{border-left:5px solid var(--line);position:relative}.risk.CRITICAL,.finding.CRITICAL{border-left-color:var(--critical)}.risk.HIGH,.finding.HIGH{border-left-color:var(--high)}.risk.MEDIUM,.finding.MEDIUM{border-left-color:var(--medium)}.risk.LOW,.finding.LOW{border-left-color:var(--low)}.risk.INFO,.finding.INFO{border-left-color:var(--info)}.badge{display:inline-block;border-radius:999px;padding:3px 8px;font-size:10px;font-weight:850;letter-spacing:.04em}.badge.CRITICAL{color:var(--critical);background:var(--critical-bg)}.badge.HIGH{color:var(--high);background:var(--high-bg)}.badge.MEDIUM{color:var(--medium);background:var(--medium-bg)}.badge.LOW{color:var(--low);background:var(--low-bg)}.badge.INFO{color:var(--info);background:var(--info-bg)}.badge.OK,.success{color:var(--ok);background:var(--ok-bg)}.badge.EXPLOITABLE{color:#fff;background:var(--critical)}.risk h3,.finding h3{font-size:15px;margin:9px 0 3px}.resource{color:var(--muted);font-size:12px;overflow-wrap:anywhere}.table-card{padding:0;overflow:hidden}table{border-collapse:collapse;width:100%}th{background:#f2f6f9;color:#425466;font-size:10px;text-transform:uppercase;letter-spacing:.06em;text-align:left}th,td{border-bottom:1px solid var(--line);padding:10px 13px;vertical-align:top}tr:last-child td{border-bottom:0}.finding{border-left:5px solid var(--line);padding:0;overflow:hidden}.finding-head{padding:17px 19px;background:#fbfcfd;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:12px}.finding-title{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.finding-id{font:700 12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--blue)}.finding-body{padding:18px 19px}.finding-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.detail h4{font-size:11px;color:#425466;text-transform:uppercase;letter-spacing:.06em;margin:0 0 5px}.detail p{margin:0;white-space:pre-wrap}.evidence{background:#f6f8fa;border:1px solid #e5eaf0;border-radius:8px;padding:10px 12px;margin-top:14px;display:grid;grid-template-columns:minmax(130px,.35fr) 1fr;gap:5px 12px}.evidence dt{font:650 11px ui-monospace,SFMono-Regular,Menlo,monospace;color:#475569;overflow-wrap:anywhere}.evidence dd{margin:0;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.action h3{font-size:14px;margin:0 0 9px}.action ol{margin:0;padding-left:20px}.action li+li{margin-top:7px}.muted{color:var(--muted)}.empty{padding:22px;color:var(--muted);text-align:center}.footer{margin:24px 0 4px;color:var(--muted);font-size:11px;text-align:center}.developer{margin-top:12px;display:flex;gap:10px;justify-content:center;align-items:center;flex-wrap:wrap}.developer a{background:#fff;border:1px solid var(--line);border-radius:999px;padding:7px 12px;font-size:12px;font-weight:700;color:var(--blue)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.briefing{font-size:15px;line-height:1.65}.evidence-panel{margin-top:16px}.evidence-panel h4{font-size:11px;color:#425466;text-transform:uppercase;letter-spacing:.06em;margin:0 0 8px}.evidence-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}.evidence-card{background:#f6f8fa;border:1px solid #e5eaf0;border-left:4px solid var(--blue-2);border-radius:10px;padding:12px 13px}.evidence-code{font:700 11px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--blue);letter-spacing:.03em;overflow-wrap:anywhere}.evidence-card p{margin:6px 0 0;font-size:13px;line-height:1.45}.evidence-strip{margin-top:10px;font-size:12px;color:var(--muted)}.evidence-strip div+div{margin-top:4px}
@media(max-width:980px){.grid-4,.grid-3,.grid-2,.status-row{grid-template-columns:repeat(2,minmax(0,1fr))}.masthead{align-items:flex-start}.score{border-left:0;padding-left:0}.brand img{width:130px;height:65px}.finding-grid{grid-template-columns:1fr}}
@media(max-width:620px){.page{padding:12px}.masthead{display:block;padding:18px}.brand{align-items:flex-start}.brand img{width:100px;height:50px}.score{text-align:left;margin-top:18px}.grid-4,.grid-3,.grid-2,.status-row{grid-template-columns:1fr}.nav{display:none}.finding-head{display:block}.finding-head .resource{margin-top:6px}}
@media print{body{background:#fff}.page{max-width:none;padding:0}.masthead,.card{box-shadow:none}.nav{display:none}.finding{break-inside:avoid}.section{break-before:auto}}
</style>
</head>
<body>
<main class="page">
<header class="masthead">
  <div class="brand">
    <img src="data:image/png;base64,{{.LogoBase64}}" alt="garga logo">
    <div><div class="eyebrow">Security Intelligence Report</div><h1>Elasticsearch Security Scan &amp; Assessment</h1><div class="subtitle">GET-only exposure, authentication, transport, and potential CVE matching. No credentials were sent and no cluster state was changed.</div></div>
  </div>
  <div class="score {{.HeadlineClass}}"><div class="score-value">{{.HeadlineCount}}</div><div class="score-label">{{.HeadlineLabel}}</div><small>Risk score {{.Score}} / 100 · {{.Posture}}</small></div>
</header>

<nav class="nav" aria-label="Report sections"><a href="#executive">Executive summary</a><a href="#risks">Top risks</a><a href="#targets">Targets</a><a href="#findings">Findings</a><a href="#actions">Actions</a><a href="#coverage">Coverage</a></nav>

<section class="section" id="executive">
  <div class="section-head"><h2>Executive Summary</h2><span class="section-note">Generated {{timestamp .Generated}}</span></div>
  <div class="card briefing">{{.Briefing}}</div>
  <div class="grid grid-4" style="margin-top:14px">
    <div class="card metric {{if .Summary.Critical}}CRITICAL{{else if .Summary.Findings}}HIGH{{else}}OK{{end}}"><div class="metric-label">Findings</div><div class="metric-value">{{.Summary.Findings}}</div><div class="metric-detail">{{.Summary.Exploitable}} exploitable-class</div></div>
    <div class="card metric {{if .Summary.Targets}}HIGH{{else}}OK{{end}}"><div class="metric-label">Targets with findings</div><div class="metric-value">{{.Summary.Targets}}</div><div class="metric-detail">{{.Coverage.Succeeded}} probed successfully</div></div>
    <div class="card metric {{if .Summary.CVEs}}MEDIUM{{else}}OK{{end}}"><div class="metric-label">CVE identifiers</div><div class="metric-value">{{.Summary.CVEs}}</div><div class="metric-detail">Potential signature matches</div></div>
    <div class="card metric {{if .Coverage.Failed}}CRITICAL{{else}}OK{{end}}"><div class="metric-label">Probe failures</div><div class="metric-value">{{.Coverage.Failed}}</div><div class="metric-detail">{{.Coverage.Submitted}} submitted</div></div>
  </div>
  <div class="status-row" style="margin-top:14px">
    <div class="status-cell {{postureClass .Posture}}"><span>Risk posture</span><strong>{{.Posture}}</strong><small class="muted">Score {{.Score}} / 100 from severity and exploitable-class findings.</small></div>
    <div class="status-cell CRITICAL"><span>Critical</span><strong>{{.Summary.Critical}}</strong></div>
    <div class="status-cell HIGH"><span>High</span><strong>{{.Summary.High}}</strong></div>
    <div class="status-cell MEDIUM"><span>Medium</span><strong>{{.Summary.Medium}}</strong></div>
    <div class="status-cell LOW"><span>Low</span><strong>{{.Summary.Low}}</strong></div>
    <div class="status-cell INFO"><span>Informational</span><strong>{{.Summary.Info}}</strong></div>
  </div>
</section>

<section class="section" id="risks">
  <div class="section-head"><h2>Top Risks</h2><span class="section-note">Exploitable-class first, then severity</span></div>
  {{if .TopRisks}}<div class="grid grid-3">{{range .TopRisks}}<article class="card risk {{.SeverityClass}}">{{if .Exploitable}}<span class="badge EXPLOITABLE">EXPLOITABLE</span> {{end}}<span class="badge {{.SeverityClass}}">{{.SeverityClass}}</span><h3>{{.Title}}</h3><div class="resource">{{.Target}}{{if .CVE}} · {{.CVE}}{{end}}</div><p>{{.Impact}}</p>{{if .EvidenceCards}}<div class="evidence-strip">{{range .EvidenceCards}}<div><span class="evidence-code">{{.Code}}</span> — {{.Summary}}</div>{{end}}</div>{{end}}</article>{{end}}</div>{{else}}<div class="card empty success">No scored security findings were emitted for the endpoints that were probed.</div>{{end}}
</section>

<section class="section" id="targets">
  <div class="section-head"><h2>Affected Targets</h2><span class="section-note">Inventory of endpoints that produced at least one finding</span></div>
  <div class="card table-card"><table><thead><tr><th>Target</th><th>Product</th><th>Version</th><th>Findings</th><th>Highest</th><th>Exploitable</th></tr></thead><tbody>{{range .Targets}}<tr><td class="mono">{{.Target}}</td><td>{{if .Product}}{{.Product}}{{else}}—{{end}}</td><td>{{if .Version}}{{.Version}}{{else}}—{{end}}</td><td>{{.Findings}}</td><td>{{if .Highest}}{{.Highest}}{{else}}—{{end}}</td><td>{{.Exploitable}}</td></tr>{{else}}<tr><td colspan="6" class="empty">No finding-bearing targets</td></tr>{{end}}</tbody></table></div>
</section>

<section class="section" id="findings">
  <div class="section-head"><h2>Detailed Findings</h2><span class="section-note">Cause, impact, cost if ignored, remediation, residual risk, and observed evidence</span></div>
  <div class="grid">{{range .Findings}}<article class="card finding {{.SeverityClass}}">
    <div class="finding-head"><div class="finding-title">{{if .Exploitable}}<span class="badge EXPLOITABLE">EXPLOITABLE</span>{{end}}<span class="badge {{.SeverityClass}}">{{.SeverityClass}}</span><span class="finding-id">{{.CheckID}}</span><strong>{{.Title}}</strong></div><div class="resource">{{.Category}}{{if .Resource}} · {{.Resource}}{{end}} · {{.Target}}</div></div>
    <div class="finding-body">{{if .Description}}<p>{{.Description}}</p>{{end}}<div class="finding-grid">
      <div class="detail"><h4>Why this appeared</h4><p>{{.Cause}}</p></div>
      <div class="detail"><h4>Operational and business impact</h4><p>{{.Impact}}</p></div>
      <div class="detail"><h4>What it costs if ignored</h4><p>{{.CostIfIgnored}}</p></div>
      <div class="detail"><h4>How to fix it</h4><p>{{.Fix}}</p></div>
      <div class="detail"><h4>Residual risk and confidence</h4><p>{{.ResidualRisk}}</p></div>
      <div class="detail"><h4>Detection metadata</h4><p>Confidence {{.Confidence}}{{if .Product}} · {{.Product}}{{end}}{{if .Version}} {{.Version}}{{end}}{{if .CVE}} · {{.CVE}}{{end}}{{if .CVSS}} · CVSS {{.CVSS}}{{end}}{{if .Tags}} · tags {{.Tags}}{{end}}</p></div>
    </div>
    <div class="evidence-panel"><h4>Observed evidence</h4><div class="evidence-cards">{{range .EvidenceCards}}<article class="evidence-card"><div class="evidence-code">{{.Code}}</div><p>{{.Summary}}</p></article>{{end}}</div></div>
    {{if .References}}<div class="detail" style="margin-top:13px"><h4>References</h4>{{range .References}}<div><a href="{{.}}" rel="noreferrer">{{.}}</a></div>{{end}}</div>{{end}}
    {{if .Exploitable}}<p class="metric-detail" style="margin-top:12px">{{.ExploitableNote}}</p>{{end}}</div>
  </article>{{else}}<div class="card empty success">No findings were produced.</div>{{end}}</div>
</section>

<section class="section" id="actions"><div class="section-head"><h2>Prioritized Action Plan</h2><span class="section-note">Recommendations are advisory and were not applied</span></div><div class="grid grid-4">
  <div class="card action"><h3>P0 · Immediate</h3>{{if .Actions.Immediate}}<ol>{{range .Actions.Immediate}}<li>{{.}}</li>{{end}}</ol>{{else}}<p class="muted">No immediate action.</p>{{end}}</div>
  <div class="card action"><h3>P1 · Urgent</h3>{{if .Actions.Urgent}}<ol>{{range .Actions.Urgent}}<li>{{.}}</li>{{end}}</ol>{{else}}<p class="muted">No urgent action.</p>{{end}}</div>
  <div class="card action"><h3>P2 · Planned</h3>{{if .Actions.Planned}}<ol>{{range .Actions.Planned}}<li>{{.}}</li>{{end}}</ol>{{else}}<p class="muted">No planned action.</p>{{end}}</div>
  <div class="card action"><h3>P3 · Optimization</h3>{{if .Actions.Optimization}}<ol>{{range .Actions.Optimization}}<li>{{.}}</li>{{end}}</ol>{{else}}<p class="muted">No optimization action.</p>{{end}}</div>
</div></section>

<section class="section" id="coverage"><div class="section-head"><h2>Assessment Coverage and Scanner Telemetry</h2><span class="section-note">Absence of a finding is meaningful only for successfully probed Elasticsearch endpoints</span></div>
  <div class="grid grid-4">
    <div class="card metric {{if .Coverage.Submitted}}INFO{{else}}OK{{end}}"><div class="metric-label">Probes submitted</div><div class="metric-value">{{.Coverage.Submitted}}</div><div class="metric-detail">{{.Coverage.Succeeded}} succeeded · {{.Coverage.Failed}} failed</div></div>
    <div class="card metric {{if .Summary.Critical}}CRITICAL{{else if .Summary.Findings}}HIGH{{else}}OK{{end}}"><div class="metric-label">Findings</div><div class="metric-value">{{.Summary.Findings}}</div><div class="metric-detail">{{.Summary.Exploitable}} exploitable-class</div></div>
    <div class="card metric INFO"><div class="metric-label">Duration</div><div class="metric-value">{{duration .Coverage.Duration}}</div><div class="metric-detail">GET-only assessment</div></div>
    <div class="card metric INFO"><div class="metric-label">Scanner</div><div class="metric-value">{{if .ScannerVersion}}{{.ScannerVersion}}{{else}}garga{{end}}</div><div class="metric-detail">Finding schema 0.1</div></div>
  </div>
</section>

<section class="section"><div class="card"><h2 style="margin-top:0">Report Context and Methodology</h2><div class="grid grid-2">
  <div><p><strong>Generated</strong><br>{{timestamp .Generated}}</p><p><strong>Scanner</strong><br>{{if .ScannerVersion}}{{.ScannerVersion}}{{else}}garga{{end}} · finding schema 0.1</p><p><strong>Methods</strong><br>Bounded GET requests only. No authentication, password spraying, writes, or exploit payloads.</p></div>
  <div><p>Exposure checks cover TLS, anonymous access class, missing security APIs, and public IP addressing. Vulnerability rows are signature matches against advertised versions and optional capability preconditions. They remain potential until operators confirm patch status.</p><p>The EXPLOITABLE mark highlights remotely usable compromise-class conditions. It is not confirmed exploitation. Hostname targets are not classified as public by IP checks because DNS is not resolved.</p></div>
</div></div></section>

<footer class="footer">
  <div>Generated by garga · Read-only Elasticsearch Security Assessment · No external scripts or network resources</div>
  <div class="developer"><span>Developer {{.DeveloperName}}</span><a href="{{.DeveloperLinkedInURL}}" rel="noopener noreferrer" target="_blank">LinkedIn</a><a href="{{.DeveloperGitHubURL}}" rel="noopener noreferrer" target="_blank">GitHub</a></div>
</footer>
</main>
</body>
</html>
`
