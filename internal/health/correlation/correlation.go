package correlation

import (
	"sort"
	"strings"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

// Analyze produces bounded, explainable root-cause hypotheses from existing findings.
func Analyze(findings []healthmodel.Finding) []healthmodel.Correlation {
	byRoot := make(map[string][]healthmodel.Finding)
	for _, finding := range findings {
		if finding.RootCause != "" {
			byRoot[finding.RootCause] = append(byRoot[finding.RootCause], finding)
		}
	}
	var correlations []healthmodel.Correlation
	if combined := matching(byRoot, "disk_pressure:", "disk_allocation_pressure"); len(combined) >= 2 {
		correlations = append(correlations, correlation(
			"Disk pressure is preventing normal allocation or writes",
			"Insufficient free disk on one or more data nodes is likely blocking shard allocation or causing flood-stage index blocks.",
			highestSeverity(combined), healthmodel.ConfidenceHigh, combined,
		))
	}
	if combined := matching(byRoot, "jvm_pressure:", "memory_pressure:"); len(combined) >= 2 {
		correlations = append(correlations, correlation(
			"JVM memory pressure has multiple supporting signals",
			"Heap utilization, garbage collection, or circuit-breaker evidence indicates sustained node memory pressure.",
			highestSeverity(combined), healthmodel.ConfidenceMedium, combined,
		))
	}
	if len(byRoot["shard_imbalance"]) > 0 && len(byRoot["disk_imbalance"]) > 0 {
		combined := append(append([]healthmodel.Finding(nil), byRoot["shard_imbalance"]...), byRoot["disk_imbalance"]...)
		correlations = append(correlations, correlation(
			"Shard placement is correlated with disk imbalance",
			"Uneven shard counts and disk utilization suggest allocation constraints or heterogeneous shard sizes are concentrating data.",
			highestSeverity(combined), healthmodel.ConfidenceMedium, combined,
		))
	}
	return correlations
}

func highestSeverity(findings []healthmodel.Finding) healthmodel.Severity {
	highest := healthmodel.SeverityInfo
	for _, finding := range findings {
		if healthmodel.SeverityRank(finding.Severity) > healthmodel.SeverityRank(highest) {
			highest = finding.Severity
		}
	}
	return highest
}

func matching(groups map[string][]healthmodel.Finding, prefixes ...string) []healthmodel.Finding {
	var result []healthmodel.Finding
	for root, findings := range groups {
		for _, prefix := range prefixes {
			if root == prefix || strings.HasPrefix(root, prefix) {
				result = append(result, findings...)
				break
			}
		}
	}
	return result
}

func correlation(title, cause string, severity healthmodel.Severity, confidence healthmodel.Confidence, findings []healthmodel.Finding) healthmodel.Correlation {
	ids := make([]string, 0, len(findings))
	evidence := make([]string, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		key := finding.ID + ":" + finding.Resource
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		ids = append(ids, finding.ID)
		evidence = append(evidence, key)
	}
	sort.Strings(ids)
	sort.Strings(evidence)
	return healthmodel.Correlation{Title: title, ProbableRootCause: cause, Severity: severity, Confidence: confidence, FindingIDs: ids, Evidence: evidence}
}
