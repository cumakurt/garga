package report

import (
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/model"
)

func TestVisualEvidenceAlwaysReturnsCards(t *testing.T) {
	t.Parallel()

	cases := []model.Finding{
		{},
		sampleFindings()[0],
		sampleFindings()[1],
		{
			Title:  "potential advisory",
			Target: model.Endpoint{Scheme: model.SchemeHTTPS, Host: "192.0.2.8", Port: 9200},
			CVE:    []string{"CVE-2014-3120"},
		},
	}
	for index, finding := range cases {
		cards := visualEvidence(finding)
		if len(cards) == 0 {
			t.Fatalf("case %d: visualEvidence returned no cards", index)
		}
		seen := map[string]struct{}{}
		for _, card := range cards {
			if strings.TrimSpace(card.Code) == "" || strings.TrimSpace(card.Summary) == "" {
				t.Fatalf("case %d: incomplete card %#v", index, card)
			}
			if _, exists := seen[card.Code]; exists {
				t.Fatalf("case %d: duplicate evidence code %q", index, card.Code)
			}
			seen[card.Code] = struct{}{}
		}
	}
}

func TestVisualEvidenceIncludesNativeAndObservedFacts(t *testing.T) {
	t.Parallel()

	finding := sampleFindings()[0]
	codes := evidenceCardCodes(visualEvidence(finding))
	for _, expected := range []string{"scheme-http", "observed_target", "product_identity"} {
		if !containsString(codes, expected) {
			t.Fatalf("codes = %v, missing %q", codes, expected)
		}
	}
	if containsString(codes, "transport_http") {
		t.Fatalf("scheme evidence should suppress transport_http: %v", codes)
	}
}

func TestConsoleAndHTMLAlwaysRenderVisualEvidence(t *testing.T) {
	t.Parallel()

	findings := sampleFindings()
	console := string(renderFormat(t, FormatConsole, findings))
	htmlReport := string(renderFormat(t, FormatHTML, findings))
	if strings.Count(console, "evidence") < len(findings) {
		t.Fatalf("console missing evidence rows:\n%s", console)
	}
	for _, finding := range findings {
		for _, card := range visualEvidence(finding) {
			if !strings.Contains(console, card.Code) {
				t.Fatalf("console missing evidence code %q:\n%s", card.Code, console)
			}
			if !strings.Contains(htmlReport, card.Code) {
				t.Fatalf("html missing evidence code %q:\n%s", card.Code, htmlReport)
			}
		}
	}
}

func evidenceCardCodes(cards []evidenceCard) []string {
	codes := make([]string, 0, len(cards))
	for _, card := range cards {
		codes = append(codes, card.Code)
	}
	return codes
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
