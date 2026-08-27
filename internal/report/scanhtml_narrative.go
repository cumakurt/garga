package report

import (
	"fmt"
	"strings"

	"github.com/cumakurt/garga/internal/model"
)

type findingNarrative struct {
	Category      string
	Cause         string
	Impact        string
	CostIfIgnored string
	Fix           string
	ResidualRisk  string
}

func narrativeFor(finding model.Finding) findingNarrative {
	narrative := findingNarrative{
		Category:      categoryFor(finding),
		Cause:         defaultCause(finding),
		Impact:        firstNonEmpty(finding.Description, defaultImpact(finding.Severity)),
		CostIfIgnored: defaultCost(finding.Severity),
		Fix:           firstNonEmpty(finding.Remediation, "Review the affected endpoint against Elasticsearch security guidance and close the gap."),
		ResidualRisk:  defaultResidual(finding),
	}
	switch {
	case finding.CheckID == checkAnonymousAccess:
		return anonymousNarrative(finding, narrative)
	case finding.CheckID == "garga.tls.not_enabled":
		return tlsNarrative(finding, narrative)
	case finding.CheckID == "garga.exposure.security_unconfigured":
		return securityUnconfiguredNarrative(finding, narrative)
	case finding.CheckID == "garga.exposure.public_network":
		return publicNetworkNarrative(finding, narrative)
	case strings.HasPrefix(finding.CheckID, checkPrefixVuln):
		return vulnerabilityNarrative(finding, narrative)
	default:
		return narrative
	}
}

func categoryFor(finding model.Finding) string {
	switch {
	case finding.CheckID == "garga.tls.not_enabled":
		return "Transport security"
	case finding.CheckID == checkAnonymousAccess, finding.CheckID == "garga.exposure.security_unconfigured":
		return "Authentication and authorization"
	case finding.CheckID == "garga.exposure.public_network":
		return "Network exposure"
	case strings.HasPrefix(finding.CheckID, checkPrefixVuln):
		return "Vulnerability"
	case finding.Resource != "":
		return finding.Resource
	default:
		return "Security finding"
	}
}

func tlsNarrative(finding model.Finding, narrative findingNarrative) findingNarrative {
	narrative.Cause = "The Elasticsearch HTTP interface was reached with the HTTP scheme. TLS was not used for this connection, so the assessment observed plaintext transport."
	narrative.Impact = firstNonEmpty(finding.Description, "Credentials, search queries, and document contents can be observed or modified in transit by anyone who can see the network path.")
	narrative.CostIfIgnored = "A man-in-the-middle position can steal operator credentials, API keys, or Bearer tokens, read indexed data, and inject queries. Encryption-in-transit controls required by most security programs will fail this endpoint."
	narrative.Fix = firstNonEmpty(finding.Remediation, "Enable TLS on the Elasticsearch HTTP interface, disable plaintext HTTP, and require HTTPS at any reverse proxy.")
	narrative.ResidualRisk = "garga did not inspect certificate quality, protocol versions, or cipher suites. Enabling TLS is necessary but not sufficient; weak TLS still needs a follow-up review."
	return narrative
}

func anonymousNarrative(finding model.Finding, narrative findingNarrative) findingNarrative {
	switch {
	case hasTag(finding, accessAdmin) || hasEvidencePrefix(finding, "class_admin"):
		narrative.Cause = "Unauthenticated HTTP GETs received cluster administration or superuser-equivalent evidence. Elasticsearch is treating anonymous clients as privileged operators."
		narrative.Impact = firstNonEmpty(finding.Description, "Anyone who can reach this HTTP port can administer the cluster without logging in.")
		narrative.CostIfIgnored = "This is a full-compromise class. An internet or internal attacker can read and destroy indices, change cluster settings, create privileged users, and stage ransomware or silent exfiltration. Incident response, legal, and availability costs typically dwarf the work of turning security on."
	case hasTag(finding, accessWrite) || hasEvidencePrefix(finding, "class_write"):
		narrative.Cause = "Unauthenticated responses indicate write-class access. garga did not send an index, document, or settings mutation to confirm it."
		narrative.Impact = firstNonEmpty(finding.Description, "Unauthenticated clients can likely change data or cluster state.")
		narrative.CostIfIgnored = "Integrity loss, poisoned search results, fraudulent documents, and a foothold for later privilege escalation. Restoring trustworthy data usually requires backups and a rebuild, not a configuration toggle."
	case hasTag(finding, accessRead) || hasEvidencePrefix(finding, "class_read"):
		narrative.Cause = "The indices catalog or equivalent read API responded without credentials."
		narrative.Impact = firstNonEmpty(finding.Description, "Unauthenticated clients can list indices. Document contents were not retrieved.")
		narrative.CostIfIgnored = "Index names reveal business processes, tenants, and data classes. That reconnaissance is enough to prioritize theft, and many deployments later expose search APIs that return documents to the same anonymous principal."
	default:
		narrative.Cause = "Unauthenticated requests succeeded on metadata or monitoring APIs."
		narrative.Impact = firstNonEmpty(finding.Description, "Cluster identity and health metadata are visible without logging in.")
		narrative.CostIfIgnored = "Metadata exposure helps an attacker confirm Elasticsearch, version, and topology. Combined with a public address or missing TLS, it becomes a targeting package rather than a curiosity."
	}
	narrative.Fix = firstNonEmpty(finding.Remediation, "Enable Elasticsearch security features and require authentication for HTTP APIs.")
	if hasTag(finding, "inferred") {
		narrative.ResidualRisk = "Write or admin impact is inferred from missing security APIs plus unauthenticated cluster APIs. garga did not send a state-changing request, so confirm the live anonymous role before treating the class as proven."
	} else {
		narrative.ResidualRisk = "garga did not send writes or exploit payloads. The observed GET evidence is sufficient to treat anonymous access as a production incident until authentication is enforced."
	}
	return narrative
}

func securityUnconfiguredNarrative(finding model.Finding, narrative findingNarrative) findingNarrative {
	narrative.Cause = "GET /_security/_authenticate was classified as unsupported. Native security features are disabled, not installed, or hidden behind a proxy that does not expose them."
	narrative.Impact = firstNonEmpty(finding.Description, "Native authentication, authorization, and API keys are likely unavailable. The cluster cannot enforce who may read or change data.")
	narrative.CostIfIgnored = "Without a security realm, every reachable client is an operator. That usually leads to anonymous administration findings and removes the audit trail needed after an incident."
	narrative.Fix = firstNonEmpty(finding.Remediation, "Enable Elasticsearch security features and verify that GET /_security/_authenticate is served.")
	narrative.ResidualRisk = "Unsupported security APIs can also mean a version or proxy limitation. Confirm xpack.security (or equivalent) is enabled on every HTTP node, not only that a load balancer returned 404."
	return narrative
}

func publicNetworkNarrative(finding model.Finding, narrative findingNarrative) findingNarrative {
	narrative.Cause = "The target host is a public unicast IP address. garga does not resolve hostnames, so DNS names are not classified by this check."
	narrative.Impact = firstNonEmpty(finding.Description, "The Elasticsearch HTTP port is addressed on the public Internet rather than a private or loopback interface.")
	narrative.CostIfIgnored = "Public Elasticsearch endpoints are continuously discovered by internet scanners. Combined with anonymous access, missing TLS, or a remotely usable CVE, this is how clusters become mass-compromise events rather than internal findings."
	narrative.Fix = firstNonEmpty(finding.Remediation, "Bind HTTP to a private address, place Elasticsearch behind a trusted reverse proxy, and restrict access with network policy and authentication.")
	narrative.ResidualRisk = "A hostname that points at a public IP is not flagged here. Review DNS, load-balancer addresses, and security-group exposure separately."
	return narrative
}

func vulnerabilityNarrative(finding model.Finding, narrative findingNarrative) findingNarrative {
	advisory := strings.Join(finding.CVE, ", ")
	if advisory == "" {
		advisory = finding.CheckID
	}
	version := finding.Version
	if version == "" {
		version = "the advertised version"
	}
	narrative.Cause = fmt.Sprintf("The advertised Elasticsearch version %s is in the affected range for %s. This is signature matching, not an exploit attempt.", version, advisory)
	if hasTag(finding, "version-only") {
		narrative.Cause += " Detection is version-only: required attack preconditions were not confirmed on this endpoint."
	}
	narrative.Impact = firstNonEmpty(finding.Description, "The installed version matches a published Elasticsearch advisory.")
	if finding.CVSS != nil {
		narrative.CostIfIgnored = fmt.Sprintf("Published CVSS is %.1f. Unpatched Elasticsearch HTTP ports are routinely scanned. If this advisory is remotely usable and the node is reachable, expected losses include cluster takeover, data theft, or service outage—not a cosmetic finding.", *finding.CVSS)
	} else {
		narrative.CostIfIgnored = "Leaving an affected Elasticsearch version reachable keeps a known attack path open. Patch latency is a common cause of later incident reports even when the original scan only had version evidence."
	}
	if exploitable(finding) {
		narrative.CostIfIgnored += " garga classified this advisory as a remote-compromise class (RCE, authentication bypass, unsafe deserialization, or CISA KEV). That mark is not confirmed exploitation."
	}
	narrative.Fix = firstNonEmpty(finding.Remediation, "Upgrade Elasticsearch to a version outside the affected range and confirm the vendor advisory no longer applies.")
	narrative.ResidualRisk = "Potential only: version evidence is not proof that the vulnerable code path is reachable, nor that an exploit succeeded. Confirm patch status, whether the required capability is exposed, and whether compensating controls already block the path."
	return narrative
}

func defaultCause(finding model.Finding) string {
	target := targetDisplay(finding.Target)
	if target == "" {
		target = "the assessed endpoint"
	}
	return "Observed during a GET-only assessment of " + target + "."
}

func defaultImpact(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "This condition can lead to immediate cluster compromise or data loss if an attacker can reach the endpoint."
	case model.SeverityHigh:
		return "This condition is likely to cause material confidentiality, integrity, or availability impact."
	case model.SeverityMedium:
		return "This condition enlarges the attack surface and can become a path to a higher-impact issue."
	case model.SeverityLow:
		return "Direct impact is limited, but the condition still weakens defense in depth."
	default:
		return "Informational context for operators; review against local policy."
	}
}

func defaultCost(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "Treat as an active incident until contained. Delay usually means a larger blast radius, longer recovery, and reportable data exposure."
	case model.SeverityHigh:
		return "Expected cost is a security event: credential theft, data disclosure, or service disruption if the endpoint remains reachable."
	case model.SeverityMedium:
		return "Left open, this typically becomes the reconnaissance or staging step for a later high-severity incident."
	case model.SeverityLow:
		return "Operational and compliance friction more than immediate outage, unless combined with anonymous access or a public address."
	default:
		return "No direct financial penalty is implied; retain the evidence for the security program."
	}
}

func defaultResidual(finding model.Finding) string {
	parts := []string{
		"Confidence is " + string(finding.Confidence) + ".",
		"garga uses GET-only requests and does not send exploits, credential sprays, or state-changing APIs.",
	}
	if exploitable(finding) {
		parts = append(parts, exploitableNote(finding))
	}
	return strings.Join(parts, " ")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func hasEvidencePrefix(finding model.Finding, prefix string) bool {
	for _, code := range evidenceCodes(finding) {
		if strings.HasPrefix(code, prefix) {
			return true
		}
	}
	return false
}
