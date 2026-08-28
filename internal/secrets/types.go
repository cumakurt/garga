package secrets

import "time"

const SchemaVersion = "1.1"

// MaxReportFindings bounds retained canonical findings for one scan.
const MaxReportFindings = 10000

// Confidence is the reporting certainty of a finding.
type Confidence string

const (
	ConfidenceLow       Confidence = "low"
	ConfidenceMedium    Confidence = "medium"
	ConfidenceHigh      Confidence = "high"
	ConfidenceConfirmed Confidence = "confirmed-pattern"
)

// Severity is the security impact of a finding.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Finding is one deduplicated, report-safe sensitive-data observation. Raw
// discovered values never enter this canonical model.
type Finding struct {
	ID             string            `json:"id"`
	Title          string            `json:"title"`
	Target         string            `json:"target"`
	Cluster        string            `json:"cluster"`
	Index          string            `json:"index"`
	DocumentID     string            `json:"document_id"`
	FieldPath      string            `json:"field_path"`
	ObjectPath     string            `json:"object_path,omitempty"`
	RelatedFields  []string          `json:"related_fields,omitempty"`
	CredentialType string            `json:"credential_type,omitempty"`
	Category       string            `json:"category"`
	Detector       string            `json:"detector"`
	Severity       Severity          `json:"severity"`
	Confidence     Confidence        `json:"confidence"`
	MaskedPreview  string            `json:"masked_preview"`
	MaskedValues   map[string]string `json:"masked_values,omitempty"`
	Reason         string            `json:"reason"`
	Remediation    string            `json:"remediation"`
	Timestamp      time.Time         `json:"timestamp"`
	Occurrences    int               `json:"occurrences"`

	// dedupFingerprint is an ephemeral keyed digest. Engine.Scan clears it before
	// the finding enters Result.
	dedupFingerprint string
}

// TargetReport describes one Elasticsearch endpoint after a scan attempt.
type TargetReport struct {
	Target            string `json:"target"`
	Reachable         bool   `json:"reachable"`
	Cluster           string `json:"cluster,omitempty"`
	Version           string `json:"version,omitempty"`
	Authenticated     bool   `json:"authenticated"`
	AuthIdentity      string `json:"auth_identity,omitempty"`
	IndicesInspected  int    `json:"indices_inspected"`
	DocumentsSampled  int    `json:"documents_sampled"`
	DocumentsExamined int    `json:"documents_examined,omitempty"`
	FieldsExamined    int    `json:"fields_examined,omitempty"`
	BytesExamined     int64  `json:"bytes_examined,omitempty"`
	FindingsTruncated bool   `json:"findings_truncated,omitempty"`
	Error             string `json:"error,omitempty"`
}

// Summary is the operator-facing scan rollup. It never contains secret values.
type Summary struct {
	ScanMode           ScanMode       `json:"scan_mode"`
	TargetsScanned     int            `json:"targets_scanned"`
	ReachableTargets   int            `json:"reachable_targets"`
	IndicesInspected   int            `json:"indices_inspected"`
	DocumentsSampled   int            `json:"documents_sampled"`
	DocumentsExamined  int            `json:"documents_examined"`
	FieldsExamined     int            `json:"fields_examined"`
	BytesExamined      int64          `json:"bytes_examined"`
	Findings           int            `json:"findings"`
	FieldFindings      int            `json:"field_findings"`
	CorrelatedFindings int            `json:"correlated_findings"`
	Occurrences        int            `json:"occurrences"`
	FindingsTruncated  bool           `json:"findings_truncated"`
	SeverityCounts     map[string]int `json:"severity_counts"`
	CategoryCounts     map[string]int `json:"category_counts"`
	CorrelationCounts  map[string]int `json:"correlation_counts,omitempty"`
	TopIndices         []IndexCount   `json:"top_indices,omitempty"`
	StartedAt          time.Time      `json:"started_at"`
	FinishedAt         time.Time      `json:"finished_at"`
	ScanDurationMS     int64          `json:"scan_duration_ms"`
	PartialFailures    int            `json:"partial_failures"`
}

// IndexCount ranks indices by finding count.
type IndexCount struct {
	Index string `json:"index"`
	Count int    `json:"count"`
}

// ScanReport is the canonical, report-safe output shared by every renderer.
type ScanReport struct {
	SchemaVersion string         `json:"schema_version"`
	Summary       Summary        `json:"summary"`
	Targets       []TargetReport `json:"targets"`
	Findings      []Finding      `json:"findings"`
}

// Result preserves the pre-1.1 internal name while all renderers migrate to
// the explicit canonical ScanReport name.
type Result = ScanReport

func confidenceRank(value Confidence) int {
	switch value {
	case ConfidenceConfirmed:
		return 4
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

func severityRank(value Severity) int {
	switch value {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
