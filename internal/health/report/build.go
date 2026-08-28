package report

import (
	"sort"
	"time"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/health/correlation"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
	"github.com/cumakurt/garga/internal/health/redact"
	"github.com/cumakurt/garga/internal/health/scoring"
)

type BuildOptions struct {
	ScannerVersion string
	Profile        config.HealthProfile
	Deep           bool
	Duration       time.Duration
	TopN           int
	AssessmentMode bool
}

func Build(snapshot *healthmodel.ClusterSnapshot, findings []healthmodel.Finding, checks []healthmodel.CheckResult, options BuildOptions) healthmodel.Report {
	cleaned := make([]healthmodel.Finding, len(findings))
	for index, finding := range findings {
		cleaned[index] = sanitizeFinding(finding)
	}
	score := scoring.Calculate(cleaned)
	metrics := topMetrics(snapshot, options.TopN)
	report := healthmodel.Report{
		SchemaVersion: healthmodel.ReportSchemaVersion,
		Cluster:       snapshot.Cluster,
		Metrics:       metrics,
		Findings:      cleaned,
		Correlations:  correlation.Analyze(cleaned),
		Actions:       actions(cleaned),
		Metadata: healthmodel.Metadata{
			ScannerVersion: options.ScannerVersion, ScanTimestamp: snapshot.Timestamp, DurationMillis: options.Duration.Milliseconds(), Target: snapshot.Target,
			ElasticsearchVersion: snapshot.Cluster.Version.Number, HealthProfile: string(options.Profile), DeepScanEnabled: options.Deep,
			Collectors: append([]healthmodel.CollectorResult(nil), snapshot.Collection.Collectors...), APIRequests: snapshot.Collection.Requests,
			BytesDownloaded: snapshot.Collection.Bytes, FailedRequests: snapshot.Collection.Failed, RetriedRequests: snapshot.Collection.Retried,
			AssessmentMode: options.AssessmentMode,
		},
	}
	report.Summary = healthmodel.Summary{
		OverallHealth: score.Health, HealthScore: score.Score, SeverityCounts: score.Counts,
		Nodes: snapshot.Cluster.Nodes, Indices: snapshot.Cluster.Indices, Shards: snapshot.Cluster.Shards, TotalDataBytes: snapshot.Cluster.StoreBytes,
		LargestIndex: first(metrics.TopIndicesByStorage), HighestDiskUsage: first(metrics.TopNodesByDisk), HighestJVMUsage: first(metrics.TopNodesByJVM),
		TopRisks: topRisks(cleaned, options.TopN), CheckCoverage: coverage(checks),
	}
	return report
}

func sanitizeFinding(finding healthmodel.Finding) healthmodel.Finding {
	finding.Title = redact.Text(finding.Title)
	finding.Description = redact.Text(finding.Description)
	finding.ResourceType = redact.Text(finding.ResourceType)
	finding.Resource = redact.Text(finding.Resource)
	finding.Threshold = redact.Text(finding.Threshold)
	finding.Impact = redact.Text(finding.Impact)
	finding.Recommendation = redact.Text(finding.Recommendation)
	finding.RootCause = redact.Text(finding.RootCause)
	finding.Evidence = redact.Evidence(finding.Evidence)
	for index := range finding.References {
		finding.References[index] = redact.Text(finding.References[index])
	}
	return finding
}

func topMetrics(snapshot *healthmodel.ClusterSnapshot, topN int) healthmodel.Metrics {
	if topN < 1 {
		topN = 5
	}
	metrics := healthmodel.Metrics{ClusterHealth: snapshot.ClusterHealth}
	shardsByIndex := make(map[string]int)
	shardsByNode := make(map[string]int)
	for _, shard := range snapshot.Shards {
		shardsByIndex[shard.Index]++
		if shard.Node != "" {
			shardsByNode[shard.Node]++
		}
	}
	for _, index := range snapshot.Indices {
		metrics.TopIndicesByStorage = append(metrics.TopIndicesByStorage, healthmodel.ResourceUsage{Resource: redact.Text(index.Name), Value: float64(index.StoreBytes), Unit: "bytes"})
		metrics.TopIndicesByDocuments = append(metrics.TopIndicesByDocuments, healthmodel.ResourceUsage{Resource: redact.Text(index.Name), Value: float64(index.Documents), Unit: "documents"})
		metrics.TopIndicesByShards = append(metrics.TopIndicesByShards, healthmodel.ResourceUsage{Resource: redact.Text(index.Name), Value: float64(shardsByIndex[index.Name]), Unit: "shards"})
	}
	for _, node := range snapshot.Nodes {
		if node.Filesystem.TotalBytes > 0 {
			metrics.TopNodesByDisk = append(metrics.TopNodesByDisk, healthmodel.ResourceUsage{Resource: redact.Text(node.Name), Value: fixedReport(node.Filesystem.UsedPercent()), Unit: "percent"})
		}
		if node.JVM.HeapMaxBytes > 0 {
			metrics.TopNodesByJVM = append(metrics.TopNodesByJVM, healthmodel.ResourceUsage{Resource: redact.Text(node.Name), Value: float64(node.JVM.HeapUsedPercent), Unit: "percent"})
		}
		if count := shardsByNode[node.Name]; count > 0 {
			metrics.TopNodesByShards = append(metrics.TopNodesByShards, healthmodel.ResourceUsage{Resource: redact.Text(node.Name), Value: float64(count), Unit: "shards"})
		}
	}
	metrics.TopIndicesByStorage = sortUsage(metrics.TopIndicesByStorage, topN)
	metrics.TopIndicesByDocuments = sortUsage(metrics.TopIndicesByDocuments, topN)
	metrics.TopIndicesByShards = sortUsage(metrics.TopIndicesByShards, topN)
	metrics.TopNodesByDisk = sortUsage(metrics.TopNodesByDisk, topN)
	metrics.TopNodesByJVM = sortUsage(metrics.TopNodesByJVM, topN)
	metrics.TopNodesByShards = sortUsage(metrics.TopNodesByShards, topN)
	return metrics
}

func sortUsage(values []healthmodel.ResourceUsage, limit int) []healthmodel.ResourceUsage {
	sort.SliceStable(values, func(left, right int) bool {
		if values[left].Value != values[right].Value {
			return values[left].Value > values[right].Value
		}
		return values[left].Resource < values[right].Resource
	})
	if len(values) > limit {
		values = values[:limit]
	}
	return values
}

func first(values []healthmodel.ResourceUsage) healthmodel.ResourceUsage {
	if len(values) == 0 {
		return healthmodel.ResourceUsage{}
	}
	return values[0]
}

func topRisks(findings []healthmodel.Finding, limit int) []healthmodel.Finding {
	if limit < 1 {
		limit = 5
	}
	result := make([]healthmodel.Finding, 0, limit)
	for _, finding := range findings {
		if finding.Severity == healthmodel.SeverityInfo || finding.Severity == healthmodel.SeverityOK {
			continue
		}
		result = append(result, finding)
		if len(result) == limit {
			break
		}
	}
	return result
}

func coverage(results []healthmodel.CheckResult) healthmodel.CheckCoverage {
	coverage := healthmodel.CheckCoverage{Available: len(results)}
	for _, result := range results {
		switch result.Status {
		case "passed":
			coverage.Executed++
			coverage.Passed++
		case "finding":
			coverage.Executed++
			coverage.Findings += result.Findings
		case "skipped":
			coverage.Skipped++
		case "failed":
			coverage.Failed++
		}
	}
	return coverage
}

func actions(findings []healthmodel.Finding) healthmodel.Actions {
	actions := healthmodel.Actions{}
	seen := make(map[string]struct{})
	for _, finding := range findings {
		recommendation := finding.Recommendation
		if recommendation == "" {
			continue
		}
		if _, exists := seen[recommendation]; exists {
			continue
		}
		seen[recommendation] = struct{}{}
		switch finding.Severity {
		case healthmodel.SeverityCritical:
			actions.Immediate = append(actions.Immediate, recommendation)
		case healthmodel.SeverityHigh:
			actions.Urgent = append(actions.Urgent, recommendation)
		case healthmodel.SeverityMedium:
			actions.Planned = append(actions.Planned, recommendation)
		case healthmodel.SeverityLow:
			actions.Optimization = append(actions.Optimization, recommendation)
		}
	}
	return actions
}

func fixedReport(value float64) float64 { return float64(int(value*100+0.5)) / 100 }
