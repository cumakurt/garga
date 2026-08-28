package secrets

import (
	"fmt"
	"reflect"
)

// ValidateResult enforces the canonical pre-render report invariants.
func ValidateResult(result ScanReport) error {
	if result.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema version must be %s", SchemaVersion)
	}
	if result.Summary.ScanMode != ScanModeNormal && result.Summary.ScanMode != ScanModeDeep {
		return fmt.Errorf("scan mode is invalid")
	}
	if result.Summary.StartedAt.IsZero() || result.Summary.FinishedAt.IsZero() || result.Summary.FinishedAt.Before(result.Summary.StartedAt) {
		return fmt.Errorf("scan timestamps are invalid")
	}

	seenIDs := make(map[string]struct{}, len(result.Findings))
	for index, finding := range result.Findings {
		if finding.ID == "" {
			return fmt.Errorf("finding %d has no ID", index)
		}
		if _, exists := seenIDs[finding.ID]; exists {
			return fmt.Errorf("finding ID %q is duplicated", finding.ID)
		}
		seenIDs[finding.ID] = struct{}{}
		if finding.Title == "" || finding.Category == "" || finding.Detector == "" || finding.Reason == "" || finding.Remediation == "" {
			return fmt.Errorf("finding %q is incomplete", finding.ID)
		}
		if finding.Target == "" || finding.Index == "" || finding.FieldPath == "" || finding.MaskedPreview == "" {
			return fmt.Errorf("finding %q has incomplete location or preview", finding.ID)
		}
		if !validSeverity(finding.Severity) {
			return fmt.Errorf("finding %q has invalid severity", finding.ID)
		}
		if !validConfidence(finding.Confidence) {
			return fmt.Errorf("finding %q has invalid confidence", finding.ID)
		}
		if finding.Timestamp.IsZero() {
			return fmt.Errorf("finding %q has no timestamp", finding.ID)
		}
		if finding.Occurrences < 1 {
			return fmt.Errorf("finding %q has invalid occurrence count", finding.ID)
		}
		if finding.dedupFingerprint != "" {
			return fmt.Errorf("finding %q retained an internal dedup fingerprint", finding.ID)
		}
	}

	for index, target := range result.Targets {
		if target.Target == "" {
			return fmt.Errorf("target %d has no address", index)
		}
		if target.IndicesInspected < 0 || target.DocumentsSampled < 0 || target.DocumentsExamined < 0 || target.FieldsExamined < 0 || target.BytesExamined < 0 {
			return fmt.Errorf("target %q has a negative counter", target.Target)
		}
	}

	expected := buildSummary(result.Summary.ScanMode, result.Targets, result.Findings, result.Summary.StartedAt, result.Summary.FinishedAt)
	if err := compareSummary(result.Summary, expected); err != nil {
		return err
	}
	return nil
}

func validSeverity(value Severity) bool {
	switch value {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

func validConfidence(value Confidence) bool {
	switch value {
	case ConfidenceConfirmed, ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		return true
	default:
		return false
	}
}

func compareSummary(actual, expected Summary) error {
	if actual.TargetsScanned != expected.TargetsScanned ||
		actual.ReachableTargets != expected.ReachableTargets ||
		actual.IndicesInspected != expected.IndicesInspected ||
		actual.DocumentsSampled != expected.DocumentsSampled ||
		actual.DocumentsExamined != expected.DocumentsExamined ||
		actual.FieldsExamined != expected.FieldsExamined ||
		actual.BytesExamined != expected.BytesExamined ||
		actual.Findings != expected.Findings ||
		actual.FieldFindings != expected.FieldFindings ||
		actual.CorrelatedFindings != expected.CorrelatedFindings ||
		actual.Occurrences != expected.Occurrences ||
		actual.FindingsTruncated != expected.FindingsTruncated ||
		actual.ScanDurationMS != expected.ScanDurationMS ||
		actual.PartialFailures != expected.PartialFailures {
		return fmt.Errorf("summary counters do not match canonical targets and findings")
	}
	if !reflect.DeepEqual(actual.SeverityCounts, expected.SeverityCounts) ||
		!reflect.DeepEqual(actual.CategoryCounts, expected.CategoryCounts) ||
		!reflect.DeepEqual(actual.CorrelationCounts, expected.CorrelationCounts) ||
		!reflect.DeepEqual(actual.TopIndices, expected.TopIndices) {
		return fmt.Errorf("summary distributions do not match canonical findings")
	}
	return nil
}
