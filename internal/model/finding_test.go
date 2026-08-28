package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFindingIDIsStableForEquivalentEndpoints(t *testing.T) {
	t.Parallel()

	left := Endpoint{Scheme: SchemeHTTP, Host: "192.0.2.10", Port: 9200}
	right := Endpoint{Scheme: SchemeHTTP, Host: "192.0.2.10", Port: 9200, Path: ""}
	if FindingID("garga.tls.not_enabled", left, "transport") != FindingID("garga.tls.not_enabled", right, "TRANSPORT") {
		t.Fatal("FindingID() treated equivalent endpoints or resources as different")
	}
	if FindingID("garga.tls.not_enabled", left, "transport") == FindingID("garga.exposure.anonymous_access", left, "transport") {
		t.Fatal("FindingID() ignored check ID")
	}
}

func TestDeduplicateFindingsMergesEvidenceAndOrdersDeterministically(t *testing.T) {
	t.Parallel()

	endpoint := Endpoint{Scheme: SchemeHTTP, Host: "192.0.2.10", Port: 9200}
	other := Endpoint{Scheme: SchemeHTTPS, Host: "192.0.2.11", Port: 9200}
	input := []Finding{
		{
			CheckID:  "garga.tls.not_enabled",
			ID:       FindingID("garga.tls.not_enabled", endpoint, "transport"),
			Title:    "TLS is not enabled",
			Target:   endpoint,
			Resource: "transport",
			Evidence: []Evidence{{Code: "scheme_http", Summary: "HTTP"}},
		},
		{
			CheckID:  "garga.exposure.anonymous_access",
			ID:       FindingID("garga.exposure.anonymous_access", endpoint, "anonymous"),
			Title:    "Anonymous access",
			Target:   endpoint,
			Resource: "anonymous",
			Evidence: []Evidence{{Code: "anonymous_available"}},
		},
		{
			CheckID:  "garga.tls.not_enabled",
			ID:       FindingID("garga.tls.not_enabled", endpoint, "transport"),
			Title:    "should be dropped",
			Target:   endpoint,
			Resource: "transport",
			Evidence: []Evidence{
				{Code: "scheme_http", Summary: "duplicate"},
				{Code: "plaintext_http", Summary: "no TLS"},
			},
		},
		{
			CheckID:  "garga.exposure.public_network",
			ID:       FindingID("garga.exposure.public_network", other, "network"),
			Title:    "Public address",
			Target:   other,
			Resource: "network",
		},
	}

	first := DeduplicateFindings(input)
	second := DeduplicateFindings(append([]Finding(nil), input...))
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("DeduplicateFindings() is not deterministic:\n%#v\n%#v", first, second)
	}
	if len(first) != 3 {
		t.Fatalf("findings = %d, want 3", len(first))
	}
	if first[0].CheckID != "garga.exposure.anonymous_access" || first[1].CheckID != "garga.exposure.public_network" || first[2].CheckID != "garga.tls.not_enabled" {
		t.Fatalf("order = %#v", first)
	}
	tls := first[2]
	if tls.Title != "TLS is not enabled" {
		t.Fatalf("duplicate metadata overwrote the first finding: %#v", tls)
	}
	if len(tls.Evidence) != 2 || tls.Evidence[0].Code != "plaintext_http" || tls.Evidence[1].Code != "scheme_http" {
		t.Fatalf("evidence = %#v", tls.Evidence)
	}
}

func TestDeduplicateFindingsReturnsNilForEmptyInput(t *testing.T) {
	t.Parallel()

	if DeduplicateFindings(nil) != nil || DeduplicateFindings([]Finding{}) != nil {
		t.Fatal("empty input should return nil")
	}
}

func TestFindingJSONOmitsRawBodiesAndZeroTime(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	finding := Finding{
		SchemaVersion: FindingSchemaVersion,
		ID:            "garga.tls.not_enabled|http|192.0.2.10|9200|/|transport",
		CheckID:       "garga.tls.not_enabled",
		Title:         "TLS is not enabled",
		Target:        Endpoint{Scheme: SchemeHTTP, Host: "192.0.2.10", Port: 9200},
		Product:       "Elasticsearch",
		Severity:      SeverityHigh,
		Confidence:    ConfidenceHigh,
		Evidence:      []Evidence{{Code: "scheme_http", Summary: "The endpoint used HTTP."}},
		Tags:          []string{"tls"},
		Resource:      "transport",
	}
	payload, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	encoded := string(payload)
	if strings.Contains(encoded, canary) || strings.Contains(encoded, "first_seen") || strings.Contains(encoded, "0001-01-01") {
		t.Fatalf("JSON = %s", encoded)
	}
	if !strings.Contains(encoded, `"schema_version":"`+FindingSchemaVersion+`"`) {
		t.Fatalf("JSON missing schema version: %s", encoded)
	}
}

func TestCloneFindingDoesNotAliasSlices(t *testing.T) {
	t.Parallel()

	cvss := 7.5
	seen := time.Unix(1_700_000_000, 0).UTC()
	wantSeen := seen
	original := Finding{
		Evidence:   []Evidence{{Code: "a"}},
		Tags:       []string{"tls"},
		References: []string{"https://example.invalid"},
		CVE:        []string{"CVE-2020-0000"},
		CVSS:       &cvss,
		FirstSeen:  &seen,
	}
	cloned := cloneFinding(original)
	original.Evidence[0].Code = "mutated"
	original.Tags[0] = "mutated"
	original.References[0] = "mutated"
	original.CVE[0] = "mutated"
	*original.CVSS = 1
	*original.FirstSeen = time.Unix(0, 0).UTC()
	if cloned.Evidence[0].Code != "a" || cloned.Tags[0] != "tls" || cloned.References[0] != "https://example.invalid" || cloned.CVE[0] != "CVE-2020-0000" || *cloned.CVSS != 7.5 || cloned.FirstSeen == nil || !cloned.FirstSeen.Equal(wantSeen) {
		t.Fatalf("clone aliased input: %#v", cloned)
	}
}
