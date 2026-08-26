package checks

import (
	"net/netip"

	"github.com/cumakurt/garga/internal/capability"
	"github.com/cumakurt/garga/internal/model"
)

type anonymousAccess struct{}

func (anonymousAccess) ID() string { return CheckExposureAnonymousAccess }

func (anonymousAccess) Requests() []Request { return nil }

func (check anonymousAccess) Applies(input Input) bool {
	return applicable(input) && input.Capabilities.IsAvailable(capability.NameAnonymous)
}

func (check anonymousAccess) Evaluate(input Input) []model.Finding {
	if !check.Applies(input) {
		return nil
	}
	classification := ClassifyAnonymousAccess(input.Capabilities)
	if classification.Class == AccessNone {
		return nil
	}

	finding := baseFinding(
		CheckExposureAnonymousAccess,
		anonymousTitle(classification),
		resourceAnonymous,
		input,
		anonymousSeverity(classification.Class),
		anonymousConfidence(classification),
	)
	finding.Description = anonymousDescription(classification)
	finding.Remediation = "Enable Elasticsearch security features and require authentication for HTTP APIs. Disable anonymous access unless a tightly scoped anonymous role is required."
	finding.Evidence = anonymousEvidence(classification)
	finding.References = []string{refMinimalSecure}
	finding.Tags = []string{"exposure", "authentication", string(classification.Class)}
	if classification.Inferred {
		finding.Tags = append(finding.Tags, "inferred")
	}
	return []model.Finding{finding}
}

func anonymousTitle(classification AnonymousClassification) string {
	switch classification.Class {
	case AccessMetadata:
		return "Elasticsearch allows unauthenticated metadata access"
	case AccessRead:
		return "Elasticsearch allows unauthenticated index listing"
	case AccessWrite:
		return "Elasticsearch likely allows unauthenticated writes"
	case AccessAdmin:
		if classification.Inferred {
			return "Elasticsearch likely allows unauthenticated cluster administration"
		}
		return "Elasticsearch allows unauthenticated cluster administration"
	default:
		return "Elasticsearch allows unauthenticated access"
	}
}

func anonymousDescription(classification AnonymousClassification) string {
	switch {
	case classification.Class == AccessAdmin && classification.Inferred:
		return "Security APIs are unavailable and cluster APIs responded without credentials. Write and admin operations are inferred from that posture; they were not confirmed with a state-changing request."
	case classification.Class == AccessAdmin:
		return "The anonymous user has the built-in superuser role. This was observed from GET /_security/_authenticate, not from a write or cluster-settings change."
	case classification.Class == AccessWrite && classification.Inferred:
		return "Security APIs are unavailable and unauthenticated responses were observed. Write access is inferred; garga did not send an index, document, or settings mutation."
	case classification.Class == AccessRead:
		return "Unauthenticated requests can list indices. Document contents were not retrieved."
	default:
		return "Unauthenticated requests can read cluster identity or monitoring metadata. Index listings and writes were not observed."
	}
}

func anonymousSeverity(class AccessClass) model.Severity {
	switch class {
	case AccessAdmin:
		return model.SeverityCritical
	case AccessWrite, AccessRead:
		return model.SeverityHigh
	default:
		return model.SeverityMedium
	}
}

func anonymousConfidence(classification AnonymousClassification) model.Confidence {
	if classification.Inferred {
		return model.ConfidenceMedium
	}
	return model.ConfidenceHigh
}

func anonymousEvidence(classification AnonymousClassification) []model.Evidence {
	code := "class_" + string(classification.Class)
	if classification.Inferred {
		code += "_inferred"
	}
	return []model.Evidence{{
		Code:    code,
		Summary: anonymousEvidenceSummary(classification),
	}}
}

func anonymousEvidenceSummary(classification AnonymousClassification) string {
	switch {
	case classification.Class == AccessAdmin && !classification.Inferred:
		return "Anonymous authenticate response contained the built-in superuser role."
	case classification.Inferred && classification.Class == AccessAdmin:
		return "Admin access is inferred from missing security APIs plus unauthenticated cluster APIs."
	case classification.Inferred && classification.Class == AccessWrite:
		return "Write access is inferred from missing security APIs; no mutation was sent."
	case classification.Class == AccessRead:
		return "The indices catalog API responded without credentials."
	default:
		return "Unauthenticated success was limited to metadata or monitoring APIs."
	}
}

type securityUnconfigured struct{}

func (securityUnconfigured) ID() string { return CheckExposureSecurityUnconfigured }

func (securityUnconfigured) Requests() []Request { return nil }

func (check securityUnconfigured) Applies(input Input) bool {
	return applicable(input) && input.Capabilities.Suppresses(capability.NameSecurity)
}

func (check securityUnconfigured) Evaluate(input Input) []model.Finding {
	if !check.Applies(input) {
		return nil
	}
	finding := baseFinding(
		CheckExposureSecurityUnconfigured,
		"Elasticsearch security APIs are not available",
		resourceSecurity,
		input,
		model.SeverityHigh,
		model.ConfidenceMedium,
	)
	finding.Description = "The security authenticate API was unsupported. Native authentication, authorization, and API keys are likely disabled or not installed."
	finding.Remediation = "Enable Elasticsearch security features and verify that GET /_security/_authenticate is served. Do not run a cluster without authentication in an untrusted network."
	finding.Evidence = []model.Evidence{{
		Code:    "security_api_unsupported",
		Summary: "The security API was classified as unsupported.",
	}}
	finding.References = []string{refMinimalSecure}
	finding.Tags = []string{"exposure", "authentication"}
	return []model.Finding{finding}
}

type publicNetwork struct{}

func (publicNetwork) ID() string { return CheckExposurePublicNetwork }

func (publicNetwork) Requests() []Request { return nil }

func (check publicNetwork) Applies(input Input) bool {
	if !applicable(input) {
		return false
	}
	_, ok := publicAddress(input.Endpoint.Host)
	return ok
}

func (check publicNetwork) Evaluate(input Input) []model.Finding {
	if !check.Applies(input) {
		return nil
	}
	finding := baseFinding(
		CheckExposurePublicNetwork,
		"Elasticsearch is addressed on a public network",
		resourceNetwork,
		input,
		model.SeverityMedium,
		model.ConfidenceHigh,
	)
	finding.Description = "The target is a public IP address. Hostnames are not resolved, so DNS names are not classified by this check."
	finding.Remediation = "Bind the HTTP interface to a private address, place Elasticsearch behind a trusted reverse proxy, and restrict access with network policy and authentication."
	finding.Evidence = []model.Evidence{{
		Code:    "address_public",
		Summary: "The endpoint host is a public IP address.",
	}}
	finding.References = []string{refMinimalSecure}
	finding.Tags = []string{"exposure", "network"}
	return []model.Finding{finding}
}

func publicAddress(host string) (netip.Addr, bool) {
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsMulticast() {
		return netip.Addr{}, false
	}
	return address, true
}
