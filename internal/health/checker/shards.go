package checker

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cumakurt/garga/internal/config"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func shardCount(profile config.HealthProfile) Checker {
	return newChecker("ES-SHARD-002", "Shard count per data node", "Capacity", "Combines heap, role, version, configured shard limits, and average shard size.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "shards") || !collectionSucceeded(snapshot, "nodes_info") {
			return nil, skip("shard_or_node_metrics_unavailable")
		}
		if len(snapshot.Nodes) == 0 {
			return nil, skip("shard_or_node_metrics_unavailable")
		}
		counts := make(map[string]int)
		bytesByNode := make(map[string]int64)
		for _, shard := range snapshot.Shards {
			if shard.Node != "" && (shard.State == "STARTED" || shard.State == "RELOCATING") {
				counts[shard.Node]++
				bytesByNode[shard.Node] += shard.StoreBytes
			}
		}
		configuredLimit := 1000
		if raw, ok := snapshot.ClusterSettings.Effective("cluster.max_shards_per_node"); ok {
			if parsed, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && parsed > 0 {
				configuredLimit = parsed
			}
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			if !node.HasDataRole() {
				continue
			}
			count := counts[node.Name]
			heapLimit := configuredLimit
			if node.JVM.HeapMaxBytes > 0 {
				heapGB := float64(node.JVM.HeapMaxBytes) / float64(1<<30)
				heapLimit = int(heapGB * 20)
				if heapLimit < 100 {
					heapLimit = 100
				}
			}
			if profile == config.HealthProfileLogging {
				heapLimit = int(float64(heapLimit) * 1.25)
			}
			limit := heapLimit
			if configuredLimit < limit {
				limit = configuredLimit
			}
			if limit <= 0 || count <= limit {
				continue
			}
			severity := healthmodel.SeverityMedium
			if count >= int(float64(limit)*1.5) {
				severity = healthmodel.SeverityHigh
			}
			averageBytes := int64(0)
			if count > 0 {
				averageBytes = bytesByNode[node.Name] / int64(count)
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "High shard count relative to node capacity", ResourceType: "node", Resource: node.Name,
				Evidence:  map[string]any{"shards": count, "heap_max_bytes": node.JVM.HeapMaxBytes, "heap_based_guideline": heapLimit, "cluster_max_shards_per_node": configuredLimit, "effective_guideline": limit, "average_shard_bytes": averageBytes, "roles": node.Roles, "elasticsearch_version": snapshot.Cluster.Version.Number},
				Threshold: "contextual heuristic: min(cluster.max_shards_per_node, 20 shards/GB heap with safeguards)", Impact: "Oversharding consumes heap, file descriptors, cluster-state resources, and recovery time.",
				Recommendation: "Consolidate small shards with rollover and lifecycle changes; validate the final target against workload and recovery objectives.", Confidence: healthmodel.ConfidenceMedium, RootCause: "oversharding",
			})
		}
		return findings, nil
	})
}

func smallShards(threshold int64) Checker {
	return newChecker("ES-SHARD-003", "Small shards", "Shard", "Detects systemic oversharding while excluding empty shards.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "shards") {
			return nil, skip("shard_metrics_unavailable")
		}
		started, small := 0, 0
		var smallBytes int64
		for _, shard := range snapshot.Shards {
			if shard.State != "STARTED" || shard.StoreBytes <= 0 {
				continue
			}
			started++
			if shard.StoreBytes < threshold {
				small++
				smallBytes += shard.StoreBytes
			}
		}
		if started == 0 || small < 20 {
			return nil, nil
		}
		ratio := float64(small) / float64(started) * 100
		if ratio < 20 {
			return nil, nil
		}
		severity := healthmodel.SeverityMedium
		if small >= 100 && ratio >= 50 {
			severity = healthmodel.SeverityHigh
		}
		return []healthmodel.Finding{{
			Severity: severity, Title: "Excessive small shards indicate oversharding", ResourceType: "cluster", Resource: snapshot.Cluster.Name,
			Evidence:  map[string]any{"small_shards": small, "started_non_empty_shards": started, "small_shard_percent": fixed(ratio), "small_threshold_bytes": threshold, "average_small_shard_bytes": smallBytes / int64(small)},
			Threshold: fmt.Sprintf("at least 20 shards below %d bytes and at least 20%% of non-empty started shards", threshold), Impact: "Many small shards increase cluster-state, heap, file, and search fan-out overhead.",
			Recommendation: "Use rollover and lifecycle policies to target larger shard sizes and consolidate future indices; do not force-merge active write indices as a blanket remedy.", Confidence: healthmodel.ConfidenceHigh, RootCause: "oversharding",
		}}, nil
	})
}

func largeShards(warning, high int64) Checker {
	return newChecker("ES-SHARD-004", "Large shards", "Shard", "Detects recovery-sensitive shard sizes using configurable thresholds.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "shards") {
			return nil, skip("shard_metrics_unavailable")
		}
		shards := append([]healthmodel.Shard(nil), snapshot.Shards...)
		sort.Slice(shards, func(left, right int) bool { return shards[left].StoreBytes > shards[right].StoreBytes })
		var findings []healthmodel.Finding
		for _, shard := range shards {
			if shard.StoreBytes < warning {
				break
			}
			severity := healthmodel.SeverityMedium
			if shard.StoreBytes >= high {
				severity = healthmodel.SeverityHigh
			}
			role := "replica"
			if shard.Primary {
				role = "primary"
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Large shard may extend recovery time", ResourceType: "shard", Resource: fmt.Sprintf("%s/%d/%s", shard.Index, shard.Number, role),
				Evidence: map[string]any{"store_bytes": shard.StoreBytes, "state": shard.State, "node": shard.Node, "primary": shard.Primary}, Threshold: fmt.Sprintf("warning %d bytes, high %d bytes", warning, high),
				Impact: "Large shards take longer to relocate, recover, merge, and snapshot.", Recommendation: "Adjust rollover and primary-shard strategy for future data. Validate any change against workload and recovery throughput.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "large_shards:" + shard.Index,
			})
			if len(findings) >= 20 {
				break
			}
		}
		return findings, nil
	})
}

func shardImbalance(threshold config.VariationThreshold) Checker {
	return newChecker("ES-SHARD-005", "Shard distribution imbalance", "Shard", "Measures shard-count distribution with mean, median, deviation, and coefficient of variation.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "shards") || !collectionSucceeded(snapshot, "nodes_info") {
			return nil, skip("shard_or_node_metrics_unavailable")
		}
		counts := make(map[string]int)
		for _, shard := range snapshot.Shards {
			if shard.Node != "" && shard.State != "UNASSIGNED" {
				counts[shard.Node]++
			}
		}
		var values []float64
		highestName, highest := "", 0
		for _, node := range snapshot.Nodes {
			if !node.HasDataRole() {
				continue
			}
			count := counts[node.Name]
			values = append(values, float64(count))
			if count > highest {
				highestName, highest = node.Name, count
			}
		}
		if len(values) < 2 {
			return nil, nil
		}
		mean, median, deviation, coefficient := stats(values)
		if coefficient < threshold.Warning {
			return nil, nil
		}
		severity := healthmodel.SeverityMedium
		if coefficient >= threshold.High {
			severity = healthmodel.SeverityHigh
		}
		return []healthmodel.Finding{{
			Severity: severity, Title: "Shard counts are imbalanced across data nodes", ResourceType: "cluster", Resource: snapshot.Cluster.Name,
			Evidence:  map[string]any{"highest_node": highestName, "highest_shards": highest, "mean": mean, "median": median, "standard_deviation": deviation, "coefficient_of_variation": coefficient, "data_nodes": len(values)},
			Threshold: fmt.Sprintf("coefficient of variation warning %.2f, high %.2f", threshold.Warning, threshold.High), Impact: "Uneven shard placement concentrates heap, CPU, disk, and recovery load.",
			Recommendation: "Inspect allocation awareness, filters, tiers, disk watermarks, and heterogeneous node capacity before rebalancing.", Confidence: healthmodel.ConfidenceHigh, RootCause: "shard_imbalance",
		}}, nil
	})
}
