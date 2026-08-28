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
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

type evidenceRow struct {
	Key   string
	Value string
}

type healthHTMLDocument struct {
	Report               healthmodel.Report
	LogoBase64           string
	Generated            time.Time
	DeveloperName        string
	DeveloperGitHubURL   string
	DeveloperLinkedInURL string
	Title                string
	Subtitle             string
	EngineLabel          string
}

var (
	healthHTMLOnce     sync.Once
	healthHTMLTemplate *template.Template
	healthHTMLParseErr error
)

func writeHTML(output io.Writer, report healthmodel.Report) error {
	healthHTMLOnce.Do(func() {
		healthHTMLTemplate, healthHTMLParseErr = template.New("health-report").Funcs(template.FuncMap{
			"bytes":         formatBytes,
			"duration":      formatDurationMillis,
			"evidence":      evidenceRows,
			"lower":         strings.ToLower,
			"severityCount": severityCount,
			"timestamp":     formatTimestamp,
			"usage":         formatUsage,
			"healthTone":    healthTone,
		}).Parse(healthHTMLSource)
	})
	if healthHTMLParseErr != nil {
		return fmt.Errorf("prepare health HTML report: %w", healthHTMLParseErr)
	}
	document := healthHTMLDocument{
		Report:               report,
		LogoBase64:           garga.LogoPNGBase64(),
		Generated:            time.Now().UTC(),
		DeveloperName:        garga.DeveloperName,
		DeveloperGitHubURL:   garga.DeveloperGitHubURL,
		DeveloperLinkedInURL: garga.DeveloperLinkedInURL,
		Title:                healthReportTitle(report),
		Subtitle:             healthReportSubtitle(report),
		EngineLabel:          healthEngineLabel(report),
	}
	if err := healthHTMLTemplate.Execute(output, document); err != nil {
		return fmt.Errorf("write health HTML report: %w", err)
	}
	return nil
}

func evidenceRows(evidence map[string]any) []evidenceRow {
	keys := make([]string, 0, len(evidence))
	for key := range evidence {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := make([]evidenceRow, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, evidenceRow{Key: key, Value: fmt.Sprint(evidence[key])})
	}
	return rows
}

func formatDurationMillis(milliseconds int64) string {
	if milliseconds < 1000 {
		return fmt.Sprintf("%d ms", milliseconds)
	}
	return (time.Duration(milliseconds) * time.Millisecond).Round(time.Millisecond).String()
}

func formatTimestamp(value time.Time) string {
	if value.IsZero() {
		return "Not available"
	}
	return value.UTC().Format("2006-01-02 15:04:05 MST")
}

func formatUsage(value healthmodel.ResourceUsage) string {
	switch value.Unit {
	case "bytes":
		return formatBytes(int64(value.Value))
	case "percent":
		return fmt.Sprintf("%.2f%%", value.Value)
	default:
		return fmt.Sprintf("%.2f %s", value.Value, value.Unit)
	}
}

func severityCount(counts map[healthmodel.Severity]int, severity string) int {
	return counts[healthmodel.Severity(severity)]
}

func healthTone(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "CRITICAL"
	case "degraded":
		return "HIGH"
	case "healthy":
		return "OK"
	default:
		return "INFO"
	}
}

func healthReportTitle(report healthmodel.Report) string {
	if report.Metadata.AssessmentMode {
		return "Elasticsearch Security and Health Assessment"
	}
	return "Elasticsearch Health Check and Assessment"
}

func healthReportSubtitle(report healthmodel.Report) string {
	if report.Metadata.AssessmentMode {
		return "Context-aware evaluation of Elasticsearch vulnerabilities, runtime consistency, configuration, health, and resilience. No exploit or state-changing operation was performed."
	}
	return "Evidence-based evaluation of cluster health, capacity, performance, reliability, configuration, and security. No state-changing Elasticsearch operation was performed."
}

func healthEngineLabel(report healthmodel.Report) string {
	if report.Metadata.AssessmentMode {
		return "Read-only Elasticsearch Security Assessment Engine"
	}
	return "Read-only Elasticsearch Health Assessment Engine"
}

const healthHTMLSource = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light">
<title>garga {{.Title}} — {{.Report.Cluster.Name}}</title>
<style>
:root{--blue:#075985;--blue-2:#0b6ea8;--teal:#0f766e;--ink:#172033;--muted:#5f6b7a;--line:#d9e2ec;--panel:#fff;--canvas:#f4f7fa;--critical:#b42318;--critical-bg:#fff0ee;--high:#c2410c;--high-bg:#fff4e8;--medium:#a16207;--medium-bg:#fff9db;--low:#0369a1;--low-bg:#edf8ff;--info:#475569;--info-bg:#f1f5f9;--ok:#15803d;--ok-bg:#edfaf1;--shadow:0 10px 30px rgba(15,45,70,.08)}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}.page{max-width:1440px;margin:0 auto;padding:30px}.masthead{background:linear-gradient(120deg,#fff 0%,#f7fbfe 70%,#edf7fb 100%);border:1px solid var(--line);border-top:6px solid var(--blue-2);border-radius:14px;box-shadow:var(--shadow);padding:24px 28px;display:flex;gap:28px;justify-content:space-between;align-items:center}.brand{display:flex;gap:20px;align-items:center}.brand img{width:176px;height:88px;object-fit:contain}.eyebrow{color:var(--blue-2);font-weight:800;letter-spacing:.12em;text-transform:uppercase;font-size:11px}.brand h1{font-size:27px;line-height:1.15;margin:5px 0 8px}.subtitle{color:var(--muted);max-width:760px}.score{min-width:200px;text-align:center;padding:18px 22px;border-radius:14px;border:1px solid var(--line);background:#fff}.score-value{font-size:48px;font-weight:850;line-height:1;color:var(--blue)}.score-label{font-weight:750;margin-top:7px}.score small{color:var(--muted);display:block;margin-top:6px}.score.CRITICAL{background:var(--critical-bg);border-color:#f0c2bd}.score.HIGH{background:var(--high-bg);border-color:#f3d0b5}.score.MEDIUM{background:var(--medium-bg);border-color:#ead889}.score.LOW{background:var(--low-bg);border-color:#bdd9ee}.score.INFO{background:var(--info-bg);border-color:#d5dde6}.score.OK{background:var(--ok-bg);border-color:#c6e6cf}.score.CRITICAL .score-value,.score.CRITICAL .score-label{color:var(--critical)}.score.HIGH .score-value,.score.HIGH .score-label{color:var(--high)}.score.MEDIUM .score-value,.score.MEDIUM .score-label{color:var(--medium)}.score.LOW .score-value,.score.LOW .score-label{color:var(--low)}.score.INFO .score-value,.score.INFO .score-label{color:var(--info)}.score.OK .score-value,.score.OK .score-label{color:var(--ok)}.nav{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}.nav a{background:#fff;border:1px solid var(--line);border-radius:999px;padding:7px 12px;font-size:12px;font-weight:700}.section{margin-top:22px}.section-head{display:flex;align-items:end;justify-content:space-between;gap:16px;margin:0 0 10px}.section h2{font-size:19px;margin:0}.section-note{color:var(--muted);font-size:12px}.grid{display:grid;gap:14px}.grid-4{grid-template-columns:repeat(4,minmax(0,1fr))}.grid-3{grid-template-columns:repeat(3,minmax(0,1fr))}.grid-2{grid-template-columns:repeat(2,minmax(0,1fr))}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 4px 16px rgba(15,45,70,.045);padding:17px}.card.metric{border-left:5px solid var(--line)}.card.metric.CRITICAL,.status-cell.CRITICAL{background:var(--critical-bg);border-color:#f0c2bd}.card.metric.HIGH,.status-cell.HIGH{background:var(--high-bg);border-color:#f3d0b5}.card.metric.MEDIUM,.status-cell.MEDIUM{background:var(--medium-bg);border-color:#ead889}.card.metric.LOW,.status-cell.LOW{background:var(--low-bg);border-color:#bdd9ee}.card.metric.INFO,.status-cell.INFO{background:var(--info-bg);border-color:#d5dde6}.card.metric.OK,.status-cell.OK{background:var(--ok-bg);border-color:#c6e6cf}.card.metric.CRITICAL,.status-cell.CRITICAL{border-left:5px solid var(--critical)}.card.metric.HIGH,.status-cell.HIGH{border-left:5px solid var(--high)}.card.metric.MEDIUM,.status-cell.MEDIUM{border-left:5px solid var(--medium)}.card.metric.LOW,.status-cell.LOW{border-left:5px solid var(--low)}.card.metric.INFO,.status-cell.INFO{border-left:5px solid var(--info)}.card.metric.OK,.status-cell.OK{border-left:5px solid var(--ok)}.card.metric.CRITICAL .metric-value,.status-cell.CRITICAL strong{color:var(--critical)}.card.metric.HIGH .metric-value,.status-cell.HIGH strong{color:var(--high)}.card.metric.MEDIUM .metric-value,.status-cell.MEDIUM strong{color:var(--medium)}.card.metric.LOW .metric-value,.status-cell.LOW strong{color:var(--low)}.card.metric.INFO .metric-value,.status-cell.INFO strong{color:var(--info)}.card.metric.OK .metric-value,.status-cell.OK strong{color:var(--ok)}.metric-label{color:var(--muted);font-size:11px;font-weight:750;letter-spacing:.06em;text-transform:uppercase}.metric-value{font-size:23px;font-weight:800;margin-top:5px;overflow-wrap:anywhere}.metric-detail{font-size:12px;color:var(--muted);margin-top:3px}.status-row{display:grid;grid-template-columns:1.5fr repeat(5,1fr);gap:10px}.status-cell{border:1px solid var(--line);border-radius:10px;background:#fff;padding:13px}.status-cell strong{display:block;font-size:21px}.status-cell span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em}.risk{border-left:5px solid var(--line);position:relative}.risk.CRITICAL,.finding.CRITICAL{border-left-color:var(--critical)}.risk.HIGH,.finding.HIGH{border-left-color:var(--high)}.risk.MEDIUM,.finding.MEDIUM{border-left-color:var(--medium)}.risk.LOW,.finding.LOW{border-left-color:var(--low)}.risk.INFO,.finding.INFO{border-left-color:var(--info)}.badge{display:inline-block;border-radius:999px;padding:3px 8px;font-size:10px;font-weight:850;letter-spacing:.04em}.badge.CRITICAL{color:var(--critical);background:var(--critical-bg)}.badge.HIGH{color:var(--high);background:var(--high-bg)}.badge.MEDIUM{color:var(--medium);background:var(--medium-bg)}.badge.LOW{color:var(--low);background:var(--low-bg)}.badge.INFO{color:var(--info);background:var(--info-bg)}.badge.OK,.success{color:var(--ok);background:var(--ok-bg)}.risk h3,.finding h3{font-size:15px;margin:9px 0 3px}.resource{color:var(--muted);font-size:12px;overflow-wrap:anywhere}.table-card{padding:0;overflow:hidden}table{border-collapse:collapse;width:100%}th{background:#f2f6f9;color:#425466;font-size:10px;text-transform:uppercase;letter-spacing:.06em;text-align:left}th,td{border-bottom:1px solid var(--line);padding:10px 13px;vertical-align:top}tr:last-child td{border-bottom:0}.finding{border-left:5px solid var(--line);padding:0;overflow:hidden}.finding-head{padding:17px 19px;background:#fbfcfd;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;gap:12px}.finding-title{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.finding-id{font:700 12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--blue)}.finding-body{padding:18px 19px}.finding-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.detail h4{font-size:11px;color:#425466;text-transform:uppercase;letter-spacing:.06em;margin:0 0 5px}.detail p{margin:0;white-space:pre-wrap}.evidence{background:#f6f8fa;border:1px solid #e5eaf0;border-radius:8px;padding:10px 12px;margin-top:14px;display:grid;grid-template-columns:minmax(130px,.35fr) 1fr;gap:5px 12px}.evidence dt{font:650 11px ui-monospace,SFMono-Regular,Menlo,monospace;color:#475569;overflow-wrap:anywhere}.evidence dd{margin:0;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.correlation{border-top:4px solid var(--teal)}.action h3{font-size:14px;margin:0 0 9px}.action ol{margin:0;padding-left:20px}.action li+li{margin-top:7px}.muted{color:var(--muted)}.empty{padding:22px;color:var(--muted);text-align:center}.footer{margin:24px 0 4px;color:var(--muted);font-size:11px;text-align:center}.developer{margin-top:12px;display:flex;gap:10px;justify-content:center;align-items:center;flex-wrap:wrap}.developer a{background:#fff;border:1px solid var(--line);border-radius:999px;padding:7px 12px;font-size:12px;font-weight:700;color:var(--blue)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.collector-skipped{color:#8a5a00}.collector-failed{color:var(--critical)}
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
    <div><div class="eyebrow">{{if .Report.Metadata.AssessmentMode}}Security and Operational Intelligence Report{{else}}Operational Intelligence Report{{end}}</div><h1>{{.Title}}</h1><div class="subtitle">{{.Subtitle}}</div></div>
  </div>
  <div class="score {{healthTone .Report.Summary.OverallHealth}}"><div class="score-value">{{.Report.Summary.HealthScore}}</div><div class="score-label">{{.Report.Summary.OverallHealth}}</div><small>Overall score / 100</small></div>
</header>

<nav class="nav" aria-label="Report sections"><a href="#executive">Executive summary</a><a href="#risks">Top risks</a><a href="#resources">Resource consumers</a><a href="#findings">Findings</a><a href="#actions">Actions</a><a href="#coverage">Coverage</a></nav>

<section class="section" id="executive">
  <div class="section-head"><h2>Executive Summary</h2><span class="section-note">Scan time {{timestamp .Report.Metadata.ScanTimestamp}}</span></div>
  <div class="grid grid-4">
    <div class="card metric INFO"><div class="metric-label">Cluster</div><div class="metric-value">{{if .Report.Cluster.Name}}{{.Report.Cluster.Name}}{{else}}Unknown{{end}}</div><div class="metric-detail mono">{{.Report.Cluster.UUID}}</div></div>
    <div class="card metric INFO"><div class="metric-label">Elasticsearch</div><div class="metric-value">{{.Report.Cluster.Version.Number}}</div><div class="metric-detail">{{.Report.Cluster.Version.BuildFlavor}} / {{.Report.Cluster.Version.BuildType}}</div></div>
    <div class="card metric INFO"><div class="metric-label">Topology</div><div class="metric-value">{{.Report.Summary.Nodes}} nodes</div><div class="metric-detail">{{.Report.Cluster.DataNodes}} data nodes</div></div>
    <div class="card metric INFO"><div class="metric-label">Data footprint</div><div class="metric-value">{{bytes .Report.Summary.TotalDataBytes}}</div><div class="metric-detail">{{.Report.Summary.Indices}} indices · {{.Report.Summary.Shards}} shards · {{.Report.Cluster.Documents}} documents</div></div>
  </div>
  <div class="status-row" style="margin-top:14px">
    <div class="status-cell {{healthTone .Report.Summary.OverallHealth}}"><span>Cluster API status</span><strong>{{if .Report.Metrics.ClusterHealth.Status}}{{.Report.Metrics.ClusterHealth.Status}}{{else}}unknown{{end}}</strong><small class="muted">Overall health also includes every operational domain.</small></div>
    <div class="status-cell CRITICAL"><span>Critical</span><strong>{{severityCount .Report.Summary.SeverityCounts "CRITICAL"}}</strong></div>
    <div class="status-cell HIGH"><span>High</span><strong>{{severityCount .Report.Summary.SeverityCounts "HIGH"}}</strong></div>
    <div class="status-cell MEDIUM"><span>Medium</span><strong>{{severityCount .Report.Summary.SeverityCounts "MEDIUM"}}</strong></div>
    <div class="status-cell LOW"><span>Low</span><strong>{{severityCount .Report.Summary.SeverityCounts "LOW"}}</strong></div>
    <div class="status-cell INFO"><span>Informational</span><strong>{{severityCount .Report.Summary.SeverityCounts "INFO"}}</strong></div>
  </div>
</section>

<section class="section" id="risks">
  <div class="section-head"><h2>Top Risks</h2><span class="section-note">Highest operational impact first</span></div>
  {{if .Report.Summary.TopRisks}}<div class="grid grid-3">{{range .Report.Summary.TopRisks}}<article class="card risk {{.Severity}}"><span class="badge {{.Severity}}">{{.Severity}}</span><h3>{{.Title}}</h3><div class="resource">{{.ID}}{{if .Resource}} · {{.Resource}}{{end}}</div>{{if .Impact}}<p>{{.Impact}}</p>{{end}}</article>{{end}}</div>{{else}}<div class="card empty success">No scored operational risks were detected by the checks that executed.</div>{{end}}
</section>

<section class="section" id="resources">
  <div class="section-head"><h2>Top Resource Consumers</h2><span class="section-note">Independent descending rankings; list length is configurable</span></div>
  <div class="grid grid-3">
    <div class="card table-card"><table><thead><tr><th>Node by disk</th><th>Usage</th></tr></thead><tbody>{{range .Report.Metrics.TopNodesByDisk}}<tr><td>{{.Resource}}</td><td>{{usage .}}</td></tr>{{else}}<tr><td colspan="2" class="empty">Unavailable</td></tr>{{end}}</tbody></table></div>
    <div class="card table-card"><table><thead><tr><th>Node by JVM heap</th><th>Usage</th></tr></thead><tbody>{{range .Report.Metrics.TopNodesByJVM}}<tr><td>{{.Resource}}</td><td>{{usage .}}</td></tr>{{else}}<tr><td colspan="2" class="empty">Unavailable</td></tr>{{end}}</tbody></table></div>
    <div class="card table-card"><table><thead><tr><th>Node by shards</th><th>Count</th></tr></thead><tbody>{{range .Report.Metrics.TopNodesByShards}}<tr><td>{{.Resource}}</td><td>{{usage .}}</td></tr>{{else}}<tr><td colspan="2" class="empty">Unavailable</td></tr>{{end}}</tbody></table></div>
    <div class="card table-card"><table><thead><tr><th>Index by storage</th><th>Size</th></tr></thead><tbody>{{range .Report.Metrics.TopIndicesByStorage}}<tr><td>{{.Resource}}</td><td>{{usage .}}</td></tr>{{else}}<tr><td colspan="2" class="empty">Unavailable</td></tr>{{end}}</tbody></table></div>
    <div class="card table-card"><table><thead><tr><th>Index by documents</th><th>Count</th></tr></thead><tbody>{{range .Report.Metrics.TopIndicesByDocuments}}<tr><td>{{.Resource}}</td><td>{{usage .}}</td></tr>{{else}}<tr><td colspan="2" class="empty">Unavailable</td></tr>{{end}}</tbody></table></div>
    <div class="card table-card"><table><thead><tr><th>Index by shards</th><th>Count</th></tr></thead><tbody>{{range .Report.Metrics.TopIndicesByShards}}<tr><td>{{.Resource}}</td><td>{{usage .}}</td></tr>{{else}}<tr><td colspan="2" class="empty">Unavailable</td></tr>{{end}}</tbody></table></div>
  </div>
</section>

<section class="section" id="findings">
  <div class="section-head"><h2>Detailed Findings</h2><span class="section-note">Observed evidence, operational impact, and recommended response</span></div>
  <div class="grid">{{range .Report.Findings}}<article class="card finding {{.Severity}}">
    <div class="finding-head"><div class="finding-title"><span class="badge {{.Severity}}">{{.Severity}}</span><span class="finding-id">{{.ID}}</span><strong>{{.Title}}</strong></div><div class="resource">{{.Category}}{{if .ResourceType}} · {{.ResourceType}}{{end}}{{if .Resource}} · {{.Resource}}{{end}}</div></div>
    <div class="finding-body">{{if .Description}}<p>{{.Description}}</p>{{end}}<div class="finding-grid">
      <div class="detail"><h4>Operational impact</h4><p>{{if .Impact}}{{.Impact}}{{else}}Impact is context-dependent; review the evidence against workload and service objectives.{{end}}</p></div>
      <div class="detail"><h4>Recommended action</h4><p>{{if .Recommendation}}{{.Recommendation}}{{else}}Review the affected resource and supporting Elasticsearch metrics.{{end}}</p></div>
      {{if .Threshold}}<div class="detail"><h4>Evaluation threshold</h4><p>{{.Threshold}}</p></div>{{end}}
      {{if .Confidence}}<div class="detail"><h4>Confidence</h4><p>{{.Confidence}}{{if .RootCause}} · correlated root cause: <span class="mono">{{.RootCause}}</span>{{end}}</p></div>{{end}}
    </div>{{with evidence .Evidence}}{{if .}}<dl class="evidence">{{range .}}<dt>{{.Key}}</dt><dd>{{.Value}}</dd>{{end}}</dl>{{end}}{{end}}
    {{if .References}}<div class="detail" style="margin-top:13px"><h4>References</h4>{{range .References}}<div><a href="{{.}}" rel="noreferrer">{{.}}</a></div>{{end}}</div>{{end}}</div>
  </article>{{else}}<div class="card empty success">No findings were produced.</div>{{end}}</div>
</section>

{{if .Report.Correlations}}<section class="section"><div class="section-head"><h2>Probable Root Causes</h2><span class="section-note">Correlated evidence, not an automatic remediation decision</span></div><div class="grid grid-2">{{range .Report.Correlations}}<article class="card correlation"><span class="badge {{.Severity}}">{{.Severity}}</span><h3>{{.Title}}</h3><p>{{.ProbableRootCause}}</p><div class="metric-detail">Confidence {{.Confidence}} · Supporting checks {{range $index, $id := .FindingIDs}}{{if $index}}, {{end}}{{$id}}{{end}}</div>{{if .Evidence}}<ul>{{range .Evidence}}<li>{{.}}</li>{{end}}</ul>{{end}}</article>{{end}}</div></section>{{end}}

<section class="section" id="actions"><div class="section-head"><h2>Prioritized Action Plan</h2><span class="section-note">Recommendations are advisory and were not applied</span></div><div class="grid grid-4">
  <div class="card action"><h3>P0 · Immediate</h3>{{if .Report.Actions.Immediate}}<ol>{{range .Report.Actions.Immediate}}<li>{{.}}</li>{{end}}</ol>{{else}}<p class="muted">No immediate action.</p>{{end}}</div>
  <div class="card action"><h3>P1 · Urgent</h3>{{if .Report.Actions.Urgent}}<ol>{{range .Report.Actions.Urgent}}<li>{{.}}</li>{{end}}</ol>{{else}}<p class="muted">No urgent action.</p>{{end}}</div>
  <div class="card action"><h3>P2 · Planned</h3>{{if .Report.Actions.Planned}}<ol>{{range .Report.Actions.Planned}}<li>{{.}}</li>{{end}}</ol>{{else}}<p class="muted">No planned action.</p>{{end}}</div>
  <div class="card action"><h3>P3 · Optimization</h3>{{if .Report.Actions.Optimization}}<ol>{{range .Report.Actions.Optimization}}<li>{{.}}</li>{{end}}</ol>{{else}}<p class="muted">No optimization action.</p>{{end}}</div>
</div></section>

<section class="section" id="coverage"><div class="section-head"><h2>Assessment Coverage and Scanner Telemetry</h2><span class="section-note">Absence of a finding is meaningful only when its check executed</span></div>
  <div class="grid grid-4">
    <div class="card"><div class="metric-label">Checks</div><div class="metric-value">{{.Report.Summary.CheckCoverage.Executed}} / {{.Report.Summary.CheckCoverage.Available}}</div><div class="metric-detail">{{.Report.Summary.CheckCoverage.Passed}} passed · {{.Report.Summary.CheckCoverage.Skipped}} skipped · {{.Report.Summary.CheckCoverage.Failed}} failed</div></div>
    <div class="card"><div class="metric-label">API requests</div><div class="metric-value">{{.Report.Metadata.APIRequests}}</div><div class="metric-detail">{{.Report.Metadata.RetriedRequests}} retried · {{.Report.Metadata.FailedRequests}} failed</div></div>
    <div class="card"><div class="metric-label">Downloaded</div><div class="metric-value">{{bytes .Report.Metadata.BytesDownloaded}}</div><div class="metric-detail">Bounded response collection</div></div>
    <div class="card"><div class="metric-label">Duration</div><div class="metric-value">{{duration .Report.Metadata.DurationMillis}}</div><div class="metric-detail">Profile {{.Report.Metadata.HealthProfile}} · deep scan {{.Report.Metadata.DeepScanEnabled}}</div></div>
  </div>
  <div class="card table-card" style="margin-top:14px"><table><thead><tr><th>Collector</th><th>Cost</th><th>Status</th><th>HTTP</th><th>Reason / limitation</th></tr></thead><tbody>{{range .Report.Metadata.Collectors}}<tr><td class="mono">{{.Name}}</td><td>{{.Cost}}</td><td class="collector-{{lower .Status}}">{{.Status}}</td><td>{{if .HTTPStatus}}{{.HTTPStatus}}{{else}}—{{end}}</td><td>{{if .Reason}}{{.Reason}}{{else}}—{{end}}</td></tr>{{else}}<tr><td colspan="5" class="empty">Collector metadata unavailable</td></tr>{{end}}</tbody></table></div>
</section>

<section class="section"><div class="card"><h2 style="margin-top:0">Report Context and Methodology</h2><div class="grid grid-2">
  <div><p><strong>Target</strong><br><span class="mono">{{.Report.Metadata.Target}}</span></p><p><strong>Scanner</strong><br>garga {{.Report.Metadata.ScannerVersion}} · health schema {{.Report.SchemaVersion}}</p><p><strong>Generated</strong><br>{{timestamp .Generated}}</p></div>
  <div><p>This assessment combines cluster health, node resources, JVM, disk, shard and index architecture, workload pressure, lifecycle, backup, security, capacity, availability, and reliability evidence. The Elasticsearch cluster-health color is not used as the sole health decision.</p><p>Snapshot counters are labeled as cumulative unless a compatible baseline provides a delta. Heuristic conclusions state confidence and should be validated against workload history and service objectives before configuration changes.</p></div>
</div></div></section>

<footer class="footer">
  <div>Generated by garga · {{.EngineLabel}} · No external scripts or network resources</div>
  <div class="developer"><span>Developer {{.DeveloperName}}</span><a href="{{.DeveloperLinkedInURL}}" rel="noopener noreferrer" target="_blank">LinkedIn</a><a href="{{.DeveloperGitHubURL}}" rel="noopener noreferrer" target="_blank">GitHub</a></div>
</footer>
</main>
</body>
</html>
`
