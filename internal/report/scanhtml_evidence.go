package report

import (
	"fmt"
	"strings"

	"github.com/cumakurt/garga/internal/model"
)

type evidenceCard struct {
	Code    string
	Summary string
}

func visualEvidence(finding model.Finding) []evidenceCard {
	seen := map[string]struct{}{}
	var cards []evidenceCard
	add := func(code, summary string) {
		code = strings.TrimSpace(code)
		if code == "" {
			return
		}
		if _, exists := seen[code]; exists {
			return
		}
		seen[code] = struct{}{}
		summary = strings.TrimSpace(summary)
		if summary == "" {
			summary = "Observed during the GET-only assessment."
		}
		cards = append(cards, evidenceCard{Code: code, Summary: summary})
	}

	for _, item := range finding.Evidence {
		add(item.Code, item.Summary)
	}
	if display := targetDisplay(finding.Target); display != "" {
		add("observed_target", "The finding was produced for "+display+".")
	}
	if !hasSchemeEvidence(finding) {
		switch finding.Target.Scheme {
		case model.SchemeHTTP:
			add("transport_http", "The endpoint was reached over unencrypted HTTP.")
		case model.SchemeHTTPS:
			add("transport_https", "The endpoint was reached over HTTPS.")
		}
	}
	identity := strings.TrimSpace(strings.TrimSpace(finding.Product) + " " + strings.TrimSpace(finding.Version))
	if identity != "" {
		add("product_identity", identity+" was advertised by the endpoint.")
	}
	for _, cve := range finding.CVE {
		cve = strings.TrimSpace(cve)
		if cve == "" {
			continue
		}
		add("advisory_"+strings.ToLower(cve), cve+" matched the advertised version range. This is signature evidence, not a confirmed exploit.")
	}
	if finding.CVSS != nil {
		add("cvss_score", fmt.Sprintf("Published CVSS is %.1f.", *finding.CVSS))
	}
	if resource := strings.TrimSpace(finding.Resource); resource != "" {
		add("affected_resource", "Affected resource class: "+resource+".")
	}
	if len(cards) == 0 {
		add("observed", "The check produced this finding from GET-only product evidence.")
	}
	return cards
}

func hasSchemeEvidence(finding model.Finding) bool {
	for _, item := range finding.Evidence {
		code := strings.ToLower(item.Code)
		if strings.Contains(code, "scheme") || code == "transport_http" || code == "transport_https" {
			return true
		}
	}
	return false
}

func formatEvidenceLine(card evidenceCard) string {
	if card.Summary == "" {
		return card.Code
	}
	return card.Code + " — " + card.Summary
}

func streamingEvidence(finding model.Finding) string {
	cards := visualEvidence(finding)
	parts := make([]string, 0, len(cards))
	for _, card := range cards {
		parts = append(parts, formatEvidenceLine(card))
	}
	return strings.Join(parts, "; ")
}
