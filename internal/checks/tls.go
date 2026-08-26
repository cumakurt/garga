package checks

import "github.com/cumakurt/garga/internal/model"

type tlsNotEnabled struct{}

func (tlsNotEnabled) ID() string { return CheckTLSNotEnabled }

func (tlsNotEnabled) Requests() []Request { return nil }

func (check tlsNotEnabled) Applies(input Input) bool {
	return applicable(input) && input.Endpoint.Scheme == model.SchemeHTTP
}

func (check tlsNotEnabled) Evaluate(input Input) []model.Finding {
	if !check.Applies(input) {
		return nil
	}
	finding := baseFinding(
		CheckTLSNotEnabled,
		"Elasticsearch is exposed without TLS",
		resourceTransport,
		input,
		model.SeverityHigh,
		model.ConfidenceHigh,
	)
	finding.Description = "The service was reached over HTTP. Credentials, queries, and document contents can be observed or modified in transit."
	finding.Remediation = "Enable TLS on the Elasticsearch HTTP interface and disable plaintext HTTP. Require HTTPS at any reverse proxy in front of the cluster."
	finding.Evidence = []model.Evidence{{
		Code:    "scheme_http",
		Summary: "The Elasticsearch endpoint used the HTTP scheme.",
	}}
	finding.References = []string{refTLSSetup}
	finding.Tags = []string{"tls", "exposure"}
	return []model.Finding{finding}
}
