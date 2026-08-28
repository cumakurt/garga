package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/cumakurt/garga/internal/model"
)

type vexWriter struct {
	output io.Writer
	standardBuffer
}

func (writer *vexWriter) Write(ctx context.Context, finding model.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return writer.add(finding)
}

func (writer *vexWriter) Close() error {
	if writer.closed {
		return nil
	}
	findings := writer.finish()
	document := cyclonedxBOM{
		BOMFormat:       "CycloneDX",
		SpecVersion:     "1.6",
		Version:         1,
		Components:      vexComponents(findings),
		Vulnerabilities: vexVulnerabilities(findings),
	}
	encoder := json.NewEncoder(writer.output)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(document)
}

type cyclonedxBOM struct {
	BOMFormat       string                   `json:"bomFormat"`
	SpecVersion     string                   `json:"specVersion"`
	Version         int                      `json:"version"`
	Components      []cyclonedxComponent     `json:"components"`
	Vulnerabilities []cyclonedxVulnerability `json:"vulnerabilities"`
}

type cyclonedxComponent struct {
	BOMRef  string `json:"bom-ref"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cyclonedxVulnerability struct {
	ID         string              `json:"id"`
	Source     cyclonedxSource     `json:"source"`
	Ratings    []cyclonedxRating   `json:"ratings,omitempty"`
	Advisories []cyclonedxAdvisory `json:"advisories,omitempty"`
	Analysis   cyclonedxAnalysis   `json:"analysis"`
	Affects    []cyclonedxAffects  `json:"affects"`
	Properties []cyclonedxProperty `json:"properties,omitempty"`
}

type cyclonedxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type cyclonedxRating struct {
	Source   cyclonedxSource `json:"source"`
	Score    *float64        `json:"score,omitempty"`
	Severity string          `json:"severity"`
	Method   string          `json:"method,omitempty"`
}

type cyclonedxAdvisory struct {
	URL string `json:"url"`
}

type cyclonedxAnalysis struct {
	State  string `json:"state"`
	Detail string `json:"detail"`
}

type cyclonedxAffects struct {
	Ref string `json:"ref"`
}

type cyclonedxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func vexComponents(findings []model.Finding) []cyclonedxComponent {
	components := make(map[string]cyclonedxComponent)
	for _, finding := range findings {
		key := vexComponentKey(finding)
		if _, exists := components[key]; exists {
			continue
		}
		components[key] = cyclonedxComponent{
			BOMRef:  vexComponentRef(key),
			Type:    "application",
			Name:    vexComponentName(finding),
			Version: finding.Version,
		}
	}
	keys := make([]string, 0, len(components))
	for key := range components {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]cyclonedxComponent, 0, len(keys))
	for _, key := range keys {
		result = append(result, components[key])
	}
	return result
}

func vexVulnerabilities(findings []model.Finding) []cyclonedxVulnerability {
	result := make([]cyclonedxVulnerability, 0, len(findings))
	for _, finding := range findings {
		identifiers := finding.CVE
		if len(identifiers) == 0 {
			identifiers = []string{finding.CheckID}
		}
		for _, identifier := range identifiers {
			result = append(result, cyclonedxVulnerability{
				ID:         identifier,
				Source:     cyclonedxSource{Name: "garga", URL: "https://github.com/cumakurt/garga"},
				Ratings:    vexRatings(finding),
				Advisories: vexAdvisories(finding.References),
				Analysis:   vexAnalysis(finding),
				Affects:    []cyclonedxAffects{{Ref: vexComponentRef(vexComponentKey(finding))}},
				Properties: vexProperties(finding),
			})
		}
	}
	sort.SliceStable(result, func(left, right int) bool {
		if result[left].ID != result[right].ID {
			return result[left].ID < result[right].ID
		}
		return result[left].Affects[0].Ref < result[right].Affects[0].Ref
	})
	return result
}

func vexComponentKey(finding model.Finding) string {
	target, err := finding.Target.URL()
	if err != nil {
		target = "unknown-target"
	}
	return target + "\x00" + finding.Product + "\x00" + finding.Version
}

func vexComponentRef(key string) string {
	digest := sha256.Sum256([]byte(key))
	return "garga:component:" + hex.EncodeToString(digest[:16])
}

func vexComponentName(finding model.Finding) string {
	product := strings.TrimSpace(finding.Product)
	if product == "" {
		product = "unknown-product"
	}
	target, err := finding.Target.URL()
	if err != nil {
		return product
	}
	return product + " at " + target
}

func vexRatings(finding model.Finding) []cyclonedxRating {
	rating := cyclonedxRating{
		Source:   cyclonedxSource{Name: "garga"},
		Score:    finding.CVSS,
		Severity: string(finding.Severity),
	}
	if finding.CVSS != nil {
		rating.Method = "CVSSv3"
	}
	return []cyclonedxRating{rating}
}

func vexAdvisories(references []string) []cyclonedxAdvisory {
	if len(references) == 0 {
		return nil
	}
	unique := make(map[string]struct{}, len(references))
	for _, reference := range references {
		if value := strings.TrimSpace(reference); value != "" {
			unique[value] = struct{}{}
		}
	}
	values := make([]string, 0, len(unique))
	for reference := range unique {
		values = append(values, reference)
	}
	sort.Strings(values)
	advisories := make([]cyclonedxAdvisory, 0, len(values))
	for _, reference := range values {
		advisories = append(advisories, cyclonedxAdvisory{URL: reference})
	}
	return advisories
}

func vexAnalysis(finding model.Finding) cyclonedxAnalysis {
	if finding.Applicability == "applicable" {
		return cyclonedxAnalysis{
			State:  "exploitable",
			Detail: "Garga verified the configured runtime prerequisites represented by this finding. This does not prove successful exploitation.",
		}
	}
	return cyclonedxAnalysis{
		State:  "in_triage",
		Detail: "Garga detected the affected version or security condition, but runtime exploitability remains unverified.",
	}
}

func vexProperties(finding model.Finding) []cyclonedxProperty {
	properties := []cyclonedxProperty{
		{Name: "garga:confidence", Value: string(finding.Confidence)},
	}
	if finding.Applicability != "" {
		properties = append(properties, cyclonedxProperty{Name: "garga:applicability", Value: finding.Applicability})
	}
	if finding.KnownExploited {
		properties = append(properties, cyclonedxProperty{Name: "garga:known-exploited", Value: "true"})
	}
	if finding.EPSS != nil {
		properties = append(properties, cyclonedxProperty{Name: "garga:epss", Value: strconv.FormatFloat(*finding.EPSS, 'f', -1, 64)})
	}
	if finding.EPSSPercentile != nil {
		properties = append(properties, cyclonedxProperty{Name: "garga:epss-percentile", Value: strconv.FormatFloat(*finding.EPSSPercentile, 'f', -1, 64)})
	}
	if finding.PriorityScore != nil {
		properties = append(properties, cyclonedxProperty{Name: "garga:priority-score", Value: strconv.FormatFloat(*finding.PriorityScore, 'f', -1, 64)})
	}
	return properties
}
