package model

import "strings"

// Severity is the operational impact of a health finding.
type Severity string

const (
	SeverityOK       Severity = "OK"
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Confidence distinguishes direct API evidence from heuristic inference.
type Confidence string

const (
	ConfidenceLow    Confidence = "LOW"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceHigh   Confidence = "HIGH"
)

// Finding is one stable, actionable Elasticsearch health observation.
type Finding struct {
	ID             string         `json:"id"`
	Category       string         `json:"category"`
	Severity       Severity       `json:"severity"`
	Title          string         `json:"title"`
	Description    string         `json:"description,omitempty"`
	ResourceType   string         `json:"resource_type,omitempty"`
	Resource       string         `json:"resource,omitempty"`
	Evidence       map[string]any `json:"evidence,omitempty"`
	Threshold      string         `json:"threshold,omitempty"`
	Impact         string         `json:"impact,omitempty"`
	Recommendation string         `json:"recommendation,omitempty"`
	References     []string       `json:"references,omitempty"`
	Confidence     Confidence     `json:"confidence,omitempty"`
	RootCause      string         `json:"root_cause,omitempty"`
}

// SeverityRank provides deterministic ordering and threshold evaluation.
func SeverityRank(severity Severity) int {
	switch severity {
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
	case SeverityOK:
		return 0
	default:
		return -1
	}
}

// ParseSeverity validates a case-insensitive severity name.
func ParseSeverity(value string) (Severity, bool) {
	severity := Severity(strings.ToUpper(strings.TrimSpace(value)))
	return severity, SeverityRank(severity) >= 0
}

// StableKey identifies one check/resource pair across scans.
func (finding Finding) StableKey() string {
	return finding.ID + "\x00" + strings.ToLower(strings.TrimSpace(finding.ResourceType)) + "\x00" + strings.ToLower(strings.TrimSpace(finding.Resource))
}
