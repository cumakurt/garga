package lifecycle

import (
	"context"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/report"
)

const (
	SchemaVersion = "0.1"
	MaxFindings   = 100_000
)

type Status string

const (
	StatusNew       Status = "new"
	StatusResolved  Status = "resolved"
	StatusUnchanged Status = "unchanged"
	StatusRegressed Status = "regressed"
	StatusImproved  Status = "improved"
)

type Change struct {
	SchemaVersion string         `json:"schema_version"`
	ID            string         `json:"id"`
	Status        Status         `json:"status"`
	Reasons       []string       `json:"reasons,omitempty"`
	Previous      *model.Finding `json:"previous,omitempty"`
	Current       *model.Finding `json:"current,omitempty"`
}

type Summary struct {
	New       int `json:"new"`
	Resolved  int `json:"resolved"`
	Unchanged int `json:"unchanged"`
	Regressed int `json:"regressed"`
	Improved  int `json:"improved"`
	Total     int `json:"total"`
}

type Report struct {
	SchemaVersion string   `json:"schema_version"`
	Summary       Summary  `json:"summary"`
	Changes       []Change `json:"changes"`
}

func Compare(ctx context.Context, baseline, current io.Reader) (Report, error) {
	baselineFindings, err := decode(ctx, baseline, "baseline")
	if err != nil {
		return Report{}, err
	}
	currentFindings, err := decode(ctx, current, "current")
	if err != nil {
		return Report{}, err
	}

	keys := make(map[string]struct{}, len(baselineFindings)+len(currentFindings))
	for id := range baselineFindings {
		keys[id] = struct{}{}
	}
	for id := range currentFindings {
		keys[id] = struct{}{}
	}
	ordered := make([]string, 0, len(keys))
	for id := range keys {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)

	result := Report{SchemaVersion: SchemaVersion, Changes: make([]Change, 0, len(ordered))}
	for _, id := range ordered {
		previous, hadPrevious := baselineFindings[id]
		latest, hasCurrent := currentFindings[id]
		change := classify(id, previous, hadPrevious, latest, hasCurrent)
		result.Changes = append(result.Changes, change)
		increment(&result.Summary, change.Status)
	}
	result.Summary.Total = len(result.Changes)
	return result, nil
}

func decode(ctx context.Context, input io.Reader, label string) (map[string]model.Finding, error) {
	findings := make(map[string]model.Finding)
	err := report.DecodeJSONL(ctx, input, func(finding model.Finding) error {
		if len(findings) >= MaxFindings {
			return fmt.Errorf("%s exceeds %d findings", label, MaxFindings)
		}
		id := finding.ID
		if id == "" {
			id = model.FindingID(finding.CheckID, finding.Target, finding.Resource)
			finding.ID = id
		}
		if _, exists := findings[id]; exists {
			return fmt.Errorf("%s contains duplicate finding id", label)
		}
		findings[id] = finding
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("compare %s: %w", label, err)
	}
	return findings, nil
}

func classify(id string, previous model.Finding, hadPrevious bool, current model.Finding, hasCurrent bool) Change {
	change := Change{SchemaVersion: SchemaVersion, ID: id}
	if !hadPrevious {
		change.Status = StatusNew
		change.Current = findingPointer(current)
		return change
	}
	if !hasCurrent {
		change.Status = StatusResolved
		change.Previous = findingPointer(previous)
		return change
	}

	change.Previous = findingPointer(previous)
	change.Current = findingPointer(current)
	change.Reasons = riskReasons(previous, current)
	comparison := compareRisk(previous, current)
	switch {
	case comparison < 0:
		change.Status = StatusRegressed
	case comparison > 0:
		change.Status = StatusImproved
	default:
		change.Status = StatusUnchanged
		change.Reasons = nil
	}
	return change
}

func compareRisk(previous, current model.Finding) int {
	previousRisk := riskScore(previous)
	currentRisk := riskScore(current)
	if currentRisk > previousRisk+0.0001 {
		return -1
	}
	if currentRisk < previousRisk-0.0001 {
		return 1
	}
	return 0
}

func riskScore(finding model.Finding) float64 {
	value := float64(severityRank(finding.Severity) * 100)
	if finding.KnownExploited {
		value += 50
	}
	switch finding.Applicability {
	case "applicable":
		value += 20
	case "potential":
		value += 10
	}
	if finding.PriorityScore != nil && !math.IsNaN(*finding.PriorityScore) && !math.IsInf(*finding.PriorityScore, 0) {
		value += math.Max(0, math.Min(10, *finding.PriorityScore))
	}
	return value
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	default:
		return 0
	}
}

func riskReasons(previous, current model.Finding) []string {
	reasons := make([]string, 0, 4)
	if previous.Severity != current.Severity {
		reasons = append(reasons, "severity "+string(previous.Severity)+" -> "+string(current.Severity))
	}
	if previous.Applicability != current.Applicability {
		reasons = append(reasons, "applicability "+displayValue(previous.Applicability)+" -> "+displayValue(current.Applicability))
	}
	if previous.KnownExploited != current.KnownExploited {
		reasons = append(reasons, "known_exploited "+strconv.FormatBool(previous.KnownExploited)+" -> "+strconv.FormatBool(current.KnownExploited))
	}
	if floatValue(previous.PriorityScore) != floatValue(current.PriorityScore) {
		reasons = append(reasons, "priority_score "+floatValue(previous.PriorityScore)+" -> "+floatValue(current.PriorityScore))
	}
	return reasons
}

func floatValue(value *float64) string {
	if value == nil {
		return "unset"
	}
	return strconv.FormatFloat(*value, 'f', -1, 64)
}

func displayValue(value string) string {
	if value == "" {
		return "unset"
	}
	return value
}

func findingPointer(finding model.Finding) *model.Finding {
	value := finding
	return &value
}

func increment(summary *Summary, status Status) {
	switch status {
	case StatusNew:
		summary.New++
	case StatusResolved:
		summary.Resolved++
	case StatusUnchanged:
		summary.Unchanged++
	case StatusRegressed:
		summary.Regressed++
	case StatusImproved:
		summary.Improved++
	}
}
