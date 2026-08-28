package model

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// FindingSchemaVersion is the public streaming finding document version (ADR 0003).
const FindingSchemaVersion = "1.0"

// Severity is the impact of a finding and is independent of confidence.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Confidence is how strongly evidence supports the finding.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Evidence is a redacted, bounded observation. It must not contain response bodies,
// credentials, or arbitrary headers.
type Evidence struct {
	Code    string `json:"code"`
	Summary string `json:"summary,omitempty"`
}

// Finding is one deterministic, evidence-backed assessment result.
type Finding struct {
	SchemaVersion  string     `json:"schema_version"`
	ID             string     `json:"id"`
	CheckID        string     `json:"check_id"`
	Title          string     `json:"title"`
	Description    string     `json:"description,omitempty"`
	Target         Endpoint   `json:"target"`
	Product        string     `json:"product"`
	Version        string     `json:"version,omitempty"`
	Severity       Severity   `json:"severity"`
	Confidence     Confidence `json:"confidence"`
	CVSS           *float64   `json:"cvss,omitempty"`
	EPSS           *float64   `json:"epss,omitempty"`
	EPSSPercentile *float64   `json:"epss_percentile,omitempty"`
	PriorityScore  *float64   `json:"priority_score,omitempty"`
	KnownExploited bool       `json:"known_exploited,omitempty"`
	ThreatUpdated  *time.Time `json:"threat_updated,omitempty"`
	Applicability  string     `json:"applicability,omitempty"`
	CVE            []string   `json:"cve,omitempty"`
	Evidence       []Evidence `json:"evidence,omitempty"`
	Remediation    string     `json:"remediation,omitempty"`
	References     []string   `json:"references,omitempty"`
	FirstSeen      *time.Time `json:"first_seen,omitempty"`
	Tags           []string   `json:"tags,omitempty"`
	Resource       string     `json:"resource,omitempty"`
}

// FindingID returns a stable identity for one check, endpoint, and resource.
func FindingID(checkID string, endpoint Endpoint, resource string) string {
	return checkID + "|" + endpointKey(endpoint) + "|" + normalizeResource(resource)
}

// DeduplicateFindings keeps one finding per endpoint, check ID, and resource.
// Unique evidence is merged. Output order is by check ID, endpoint, then resource.
func DeduplicateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	type group struct {
		finding Finding
		seen    map[string]struct{}
	}
	groups := make(map[string]*group, len(findings))
	keys := make([]string, 0, len(findings))
	for _, finding := range findings {
		key := findingKey(finding)
		existing, ok := groups[key]
		if !ok {
			cloned := cloneFinding(finding)
			groups[key] = &group{finding: cloned, seen: evidenceCodes(cloned.Evidence)}
			keys = append(keys, key)
			continue
		}
		for _, item := range finding.Evidence {
			if item.Code == "" {
				continue
			}
			if _, exists := existing.seen[item.Code]; exists {
				continue
			}
			existing.seen[item.Code] = struct{}{}
			existing.finding.Evidence = append(existing.finding.Evidence, item)
		}
	}

	sort.Strings(keys)
	result := make([]Finding, 0, len(keys))
	for _, key := range keys {
		finding := groups[key].finding
		sortEvidence(finding.Evidence)
		result = append(result, finding)
	}
	return result
}

func findingKey(finding Finding) string {
	return finding.CheckID + "\x00" + endpointKey(finding.Target) + "\x00" + normalizeResource(finding.Resource)
}

func endpointKey(endpoint Endpoint) string {
	path := endpoint.Path
	if path == "" {
		path = "/"
	}
	return string(endpoint.Scheme) + "\x00" + endpoint.Host + "\x00" + strconv.Itoa(endpoint.Port) + "\x00" + path
}

func normalizeResource(resource string) string {
	return strings.ToLower(strings.TrimSpace(resource))
}

func evidenceCodes(evidence []Evidence) map[string]struct{} {
	seen := make(map[string]struct{}, len(evidence))
	for _, item := range evidence {
		if item.Code != "" {
			seen[item.Code] = struct{}{}
		}
	}
	return seen
}

func sortEvidence(evidence []Evidence) {
	sort.Slice(evidence, func(left, right int) bool {
		if evidence[left].Code != evidence[right].Code {
			return evidence[left].Code < evidence[right].Code
		}
		return evidence[left].Summary < evidence[right].Summary
	})
}

func cloneFinding(finding Finding) Finding {
	cloned := finding
	if finding.Evidence != nil {
		cloned.Evidence = append([]Evidence(nil), finding.Evidence...)
	}
	if finding.CVE != nil {
		cloned.CVE = append([]string(nil), finding.CVE...)
	}
	if finding.References != nil {
		cloned.References = append([]string(nil), finding.References...)
	}
	if finding.Tags != nil {
		cloned.Tags = append([]string(nil), finding.Tags...)
	}
	if finding.CVSS != nil {
		value := *finding.CVSS
		cloned.CVSS = &value
	}
	if finding.EPSS != nil {
		value := *finding.EPSS
		cloned.EPSS = &value
	}
	if finding.EPSSPercentile != nil {
		value := *finding.EPSSPercentile
		cloned.EPSSPercentile = &value
	}
	if finding.PriorityScore != nil {
		value := *finding.PriorityScore
		cloned.PriorityScore = &value
	}
	if finding.ThreatUpdated != nil {
		value := *finding.ThreatUpdated
		cloned.ThreatUpdated = &value
	}
	if finding.FirstSeen != nil {
		value := *finding.FirstSeen
		cloned.FirstSeen = &value
	}
	return cloned
}
