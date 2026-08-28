package report

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/cumakurt/garga/internal/model"
)

type sarifWriter struct {
	output io.Writer
	standardBuffer
}

func (writer *sarifWriter) Write(ctx context.Context, finding model.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return writer.add(finding)
}

func (writer *sarifWriter) Close() error {
	if writer.closed {
		return nil
	}
	findings := writer.finish()
	document := sarifDocument{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "garga", InformationURI: "https://github.com/cumakurt/garga", Rules: sarifRules(findings),
			}},
			Results: sarifResults(findings),
		}},
	}
	encoder := json.NewEncoder(writer.output)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(document)
}

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name,omitempty"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Message      sarifMessage      `json:"message"`
	Locations    []sarifLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints"`
	Properties   map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind,omitempty"`
}

func sarifRules(findings []model.Finding) []sarifRule {
	seen := make(map[string]struct{})
	rules := make([]sarifRule, 0)
	for _, finding := range findings {
		if _, exists := seen[finding.CheckID]; exists {
			continue
		}
		seen[finding.CheckID] = struct{}{}
		rule := sarifRule{ID: finding.CheckID, Name: finding.CheckID, ShortDescription: sarifMessage{Text: finding.Title}}
		if len(finding.References) > 0 {
			rule.HelpURI = finding.References[0]
		}
		rules = append(rules, rule)
	}
	return rules
}

func sarifResults(findings []model.Finding) []sarifResult {
	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		message := finding.Title
		if finding.Description != "" {
			message += ": " + finding.Description
		}
		result := sarifResult{
			RuleID: finding.CheckID, Level: sarifLevel(finding.Severity), Message: sarifMessage{Text: message},
			Fingerprints: map[string]string{"gargaFindingId/v1": sarifFingerprint(finding)},
			Properties:   sarifProperties(finding),
		}
		if target, err := finding.Target.URL(); err == nil {
			location := sarifLocation{
				PhysicalLocation: &sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: target}},
			}
			if resource := strings.TrimSpace(finding.Resource); resource != "" {
				location.LogicalLocations = []sarifLogicalLocation{{FullyQualifiedName: resource, Kind: "resource"}}
			}
			result.Locations = []sarifLocation{location}
		}
		results = append(results, result)
	}
	return results
}

func sarifFingerprint(finding model.Finding) string {
	if finding.ID != "" {
		return finding.ID
	}
	return model.FindingID(finding.CheckID, finding.Target, finding.Resource)
}

func sarifProperties(finding model.Finding) map[string]any {
	properties := map[string]any{
		"severity":   finding.Severity,
		"confidence": finding.Confidence,
	}
	if len(finding.CVE) > 0 {
		properties["cve"] = finding.CVE
	}
	if finding.CVSS != nil {
		properties["cvss"] = *finding.CVSS
	}
	if finding.EPSS != nil {
		properties["epss"] = *finding.EPSS
	}
	if finding.EPSSPercentile != nil {
		properties["epssPercentile"] = *finding.EPSSPercentile
	}
	if finding.KnownExploited {
		properties["knownExploited"] = true
	}
	if finding.PriorityScore != nil {
		properties["priorityScore"] = *finding.PriorityScore
	}
	if finding.Applicability != "" {
		properties["applicability"] = finding.Applicability
	}
	if len(finding.Tags) > 0 {
		properties["tags"] = finding.Tags
	}
	return properties
}

func sarifLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
