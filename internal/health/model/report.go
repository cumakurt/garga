package model

import "time"

const ReportSchemaVersion = "1.0"

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	Cluster       ClusterInfo   `json:"cluster"`
	Summary       Summary       `json:"summary"`
	Metrics       Metrics       `json:"metrics"`
	Findings      []Finding     `json:"findings"`
	Correlations  []Correlation `json:"correlations,omitempty"`
	Actions       Actions       `json:"actions"`
	Metadata      Metadata      `json:"metadata"`
}

type Summary struct {
	OverallHealth    string           `json:"overall_health"`
	HealthScore      int              `json:"health_score"`
	SeverityCounts   map[Severity]int `json:"severity_counts"`
	Nodes            int              `json:"nodes"`
	Indices          int              `json:"indices"`
	Shards           int              `json:"shards"`
	TotalDataBytes   int64            `json:"total_data_bytes"`
	LargestIndex     ResourceUsage    `json:"largest_index"`
	HighestDiskUsage ResourceUsage    `json:"highest_disk_usage"`
	HighestJVMUsage  ResourceUsage    `json:"highest_jvm_usage"`
	TopRisks         []Finding        `json:"top_risks"`
	CheckCoverage    CheckCoverage    `json:"check_coverage"`
}

type CheckCoverage struct {
	Available int `json:"available"`
	Executed  int `json:"executed"`
	Passed    int `json:"passed"`
	Findings  int `json:"findings"`
	Skipped   int `json:"skipped"`
	Failed    int `json:"failed"`
}

type ResourceUsage struct {
	Resource string  `json:"resource,omitempty"`
	Value    float64 `json:"value"`
	Unit     string  `json:"unit,omitempty"`
}

type Metrics struct {
	ClusterHealth         ClusterHealth   `json:"cluster_health"`
	TopIndicesByStorage   []ResourceUsage `json:"top_indices_by_storage,omitempty"`
	TopIndicesByDocuments []ResourceUsage `json:"top_indices_by_documents,omitempty"`
	TopIndicesByShards    []ResourceUsage `json:"top_indices_by_shards,omitempty"`
	TopNodesByDisk        []ResourceUsage `json:"top_nodes_by_disk,omitempty"`
	TopNodesByJVM         []ResourceUsage `json:"top_nodes_by_jvm,omitempty"`
	TopNodesByShards      []ResourceUsage `json:"top_nodes_by_shards,omitempty"`
}

type Correlation struct {
	Title             string     `json:"title"`
	ProbableRootCause string     `json:"probable_root_cause"`
	Severity          Severity   `json:"severity"`
	Confidence        Confidence `json:"confidence"`
	FindingIDs        []string   `json:"finding_ids"`
	Evidence          []string   `json:"evidence,omitempty"`
}

type Actions struct {
	Immediate    []string `json:"immediate,omitempty"`
	Urgent       []string `json:"urgent,omitempty"`
	Planned      []string `json:"planned,omitempty"`
	Optimization []string `json:"optimization,omitempty"`
}

type Metadata struct {
	ScannerVersion       string            `json:"scanner_version"`
	ScanTimestamp        time.Time         `json:"scan_timestamp"`
	DurationMillis       int64             `json:"duration_millis"`
	Target               string            `json:"target"`
	ElasticsearchVersion string            `json:"elasticsearch_version"`
	HealthProfile        string            `json:"health_profile"`
	DeepScanEnabled      bool              `json:"deep_scan_enabled"`
	Collectors           []CollectorResult `json:"collectors"`
	APIRequests          int               `json:"api_requests"`
	BytesDownloaded      int64             `json:"bytes_downloaded"`
	FailedRequests       int               `json:"failed_requests"`
	RetriedRequests      int               `json:"retried_requests"`
	AssessmentMode       bool              `json:"assessment_mode,omitempty"`
}

type CheckResult struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Findings int    `json:"findings"`
}
