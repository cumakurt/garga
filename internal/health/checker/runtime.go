package checker

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/cumakurt/garga/internal/health/model"
	basemodel "github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/vulnerability"
)

func nodeRuntimeDrift() Checker {
	return newChecker("ES-NODE-003", "Node runtime consistency", "Node", "Detects Elasticsearch version, JVM, and installed component drift between nodes.", func(_ context.Context, snapshot *model.ClusterSnapshot) ([]model.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_info") {
			return nil, skip("node_info_unavailable")
		}
		if len(snapshot.Nodes) < 2 {
			return nil, nil
		}
		versions := groupedNodes(snapshot.Nodes, func(node model.Node) string { return node.Version })
		jdks := groupedNodes(snapshot.Nodes, func(node model.Node) string { return strings.TrimSpace(node.JVM.Vendor + " " + node.JVM.Version) })
		components := groupedNodes(snapshot.Nodes, componentFingerprint)
		var findings []model.Finding
		if len(versions) > 1 {
			findings = append(findings, model.Finding{
				Severity: model.SeverityHigh, Title: "Elasticsearch node versions are inconsistent", ResourceType: "cluster", Resource: snapshot.Cluster.Name,
				Evidence: map[string]any{"node_versions": versions}, Threshold: "one Elasticsearch version across all nodes outside an active rolling upgrade",
				Impact: "Mixed node versions can retain patched and vulnerable code paths and make cluster behavior dependent on request routing.", Recommendation: "Complete the rolling upgrade or rollback through an authorized workflow, then verify that every node reports the intended patched version.",
				Confidence: model.ConfidenceHigh, RootCause: "node_version_drift",
			})
		}
		if len(jdks) > 1 {
			findings = append(findings, model.Finding{
				Severity: model.SeverityMedium, Title: "Elasticsearch nodes use inconsistent JVM runtimes", ResourceType: "cluster", Resource: snapshot.Cluster.Name,
				Evidence: map[string]any{"node_jvms": jdks}, Threshold: "one approved JDK vendor and patch line per node role",
				Impact: "JDK security fixes, garbage collection behavior, and TLS capabilities can differ between nodes.", Recommendation: "Standardize nodes on an Elasticsearch-supported, security-patched JDK through the normal rolling maintenance process.",
				Confidence: model.ConfidenceHigh, RootCause: "node_jvm_drift",
			})
		}
		if len(components) > 1 {
			findings = append(findings, model.Finding{
				Severity: model.SeverityMedium, Title: "Elasticsearch node components are inconsistent", ResourceType: "cluster", Resource: snapshot.Cluster.Name,
				Evidence: map[string]any{"component_sets": components}, Threshold: "role-appropriate plugin and module consistency across equivalent nodes",
				Impact: "Requests routed to different nodes can expose inconsistent features or leave only part of the cluster affected by a component vulnerability.", Recommendation: "Review component differences by node role and align plugin/module installations during an authorized rolling restart.",
				Confidence: model.ConfidenceHigh, RootCause: "node_component_drift",
			})
		}
		return findings, nil
	})
}

func groupedNodes(nodes []model.Node, value func(model.Node) string) map[string][]string {
	groups := make(map[string][]string)
	for _, node := range nodes {
		key := strings.TrimSpace(value(node))
		if key == "" {
			key = "unknown"
		}
		groups[key] = append(groups[key], node.Name)
	}
	for key := range groups {
		sort.Strings(groups[key])
	}
	return groups
}

func componentFingerprint(node model.Node) string {
	values := make([]string, 0, len(node.Components))
	for _, component := range node.Components {
		value := component.Type + ":" + component.Name
		if component.Version != "" {
			value += "@" + component.Version
		}
		values = append(values, value)
	}
	sort.Strings(values)
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ",")
}

func vulnerabilitySignatures(signatures []vulnerability.Signature) Checker {
	return newChecker("ES-VULN-001", "Context-aware vulnerability assessment", "Vulnerability", "Matches the cluster version and confirms observable advisory prerequisites.", func(_ context.Context, snapshot *model.ClusterSnapshot) ([]model.Finding, error) {
		endpoint, err := assessmentEndpoint(snapshot.Target)
		if err != nil {
			return nil, fmt.Errorf("assessment target: %w", err)
		}
		baseFindings := vulnerability.Findings(signatures, vulnerability.EvalInput{
			Endpoint: endpoint, Product: "elasticsearch", Version: snapshot.Cluster.Version.Number, Detected: snapshot.Cluster.FingerprintValid,
			Runtime: runtimeContext(snapshot),
		})
		findings := make([]model.Finding, 0, len(baseFindings))
		for _, finding := range baseFindings {
			findings = append(findings, healthVulnerabilityFinding(finding))
		}
		return findings, nil
	})
}

func assessmentEndpoint(raw string) (basemodel.Endpoint, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil {
		return basemodel.Endpoint{}, fmt.Errorf("invalid URL")
	}
	port := 0
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil {
			return basemodel.Endpoint{}, fmt.Errorf("invalid port")
		}
	}
	if port == 0 {
		if strings.EqualFold(parsed.Scheme, "https") {
			port = 443
		} else {
			port = 80
		}
	}
	return basemodel.Endpoint{Scheme: basemodel.Scheme(strings.ToLower(parsed.Scheme)), Host: parsed.Hostname(), Port: port, Path: parsed.EscapedPath()}, nil
}

func runtimeContext(snapshot *model.ClusterSnapshot) *vulnerability.RuntimeContext {
	context := &vulnerability.RuntimeContext{Settings: make(map[string]string), SettingConflicts: make(map[string]bool)}
	context.ComponentsKnown = collectionSucceeded(snapshot, "nodes_info") && len(snapshot.Nodes) > 0
	context.JVMKnown = context.ComponentsKnown
	components := make(map[string]struct{})
	realms := make(map[string]struct{})
	for _, node := range snapshot.Nodes {
		for _, component := range node.Components {
			components[component.Name] = struct{}{}
		}
		if major, ok := javaMajor(node.JVM.Version); ok {
			context.JVMajors = append(context.JVMajors, major)
		} else {
			context.JVMKnown = false
		}
		for key, value := range node.SecuritySettings {
			if previous, exists := context.Settings[key]; exists && previous != value {
				context.SettingConflicts[key] = true
			}
			context.Settings[key] = value
			if realm := realmType(key); realm != "" {
				realms[realm] = struct{}{}
			}
		}
	}
	for name := range components {
		context.Components = append(context.Components, name)
	}
	for name := range realms {
		context.Realms = append(context.Realms, name)
	}
	sort.Strings(context.Components)
	sort.Strings(context.Realms)
	sort.Ints(context.JVMajors)
	context.RealmsKnown = collectionSucceeded(snapshot, "nodes_settings") && len(snapshot.Nodes) > 0
	context.SettingsKnown = context.RealmsKnown && collectionSucceeded(snapshot, "cluster_settings")
	for key, value := range snapshot.ClusterSettings.Defaults {
		context.Settings[key] = value
	}
	for key, value := range snapshot.ClusterSettings.Persistent {
		context.Settings[key] = value
	}
	for key, value := range snapshot.ClusterSettings.Transient {
		context.Settings[key] = value
	}
	return context
}

func javaMajor(version string) (int, bool) {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "1.")
	value := version
	if index := strings.IndexAny(value, ".-_+"); index >= 0 {
		value = value[:index]
	}
	major, err := strconv.Atoi(value)
	return major, err == nil && major > 0
}

func realmType(setting string) string {
	parts := strings.Split(strings.ToLower(setting), ".")
	if len(parts) > 4 && parts[0] == "xpack" && parts[1] == "security" && parts[2] == "authc" && parts[3] == "realms" {
		return parts[4]
	}
	return ""
}

func healthVulnerabilityFinding(finding basemodel.Finding) model.Finding {
	evidenceCodes := make([]string, 0, len(finding.Evidence))
	for _, evidence := range finding.Evidence {
		evidenceCodes = append(evidenceCodes, evidence.Code)
	}
	evidence := map[string]any{
		"cve": finding.CVE, "known_exploited": finding.KnownExploited, "applicability": finding.Applicability,
		"evidence_codes": evidenceCodes,
	}
	if finding.CVSS != nil {
		evidence["cvss"] = *finding.CVSS
	}
	if finding.EPSS != nil {
		evidence["epss"] = *finding.EPSS
	}
	if finding.EPSSPercentile != nil {
		evidence["epss_percentile"] = *finding.EPSSPercentile
	}
	if finding.PriorityScore != nil {
		evidence["priority_score"] = *finding.PriorityScore
	}
	if finding.ThreatUpdated != nil {
		evidence["threat_updated"] = finding.ThreatUpdated.UTC().Format("2006-01-02")
	}
	return model.Finding{
		ID: finding.CheckID, Category: "Vulnerability", Severity: healthSeverity(finding.Severity), Title: finding.Title, Description: finding.Description,
		ResourceType: "vulnerability", Resource: strings.Join(finding.CVE, ","), Evidence: evidence, Threshold: "version and observable advisory prerequisites",
		Impact: "The affected Elasticsearch code path may be present; applicability does not prove successful exploitation.", Recommendation: finding.Remediation,
		References: append([]string(nil), finding.References...), Confidence: healthConfidence(finding.Confidence), RootCause: "vulnerability:" + finding.CheckID,
	}
}

func healthSeverity(severity basemodel.Severity) model.Severity {
	parsed, _ := model.ParseSeverity(string(severity))
	return parsed
}

func healthConfidence(confidence basemodel.Confidence) model.Confidence {
	switch confidence {
	case basemodel.ConfidenceHigh:
		return model.ConfidenceHigh
	case basemodel.ConfidenceMedium:
		return model.ConfidenceMedium
	default:
		return model.ConfidenceLow
	}
}
