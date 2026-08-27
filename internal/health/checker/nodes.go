package checker

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/config"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func jvmHeap(threshold config.PercentThreshold) Checker {
	return newChecker("ES-JVM-001", "JVM heap utilization", "JVM", "Evaluates per-node heap pressure without inferring a memory leak from one snapshot.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			if node.JVM.HeapMaxBytes <= 0 {
				continue
			}
			value := float64(node.JVM.HeapUsedPercent)
			if value == 0 && node.JVM.HeapUsedBytes > 0 {
				value = percentage(node.JVM.HeapUsedBytes, node.JVM.HeapMaxBytes)
			}
			severity := percentSeverity(value, threshold)
			if severity == healthmodel.SeverityOK {
				continue
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "High JVM heap utilization", ResourceType: "node", Resource: node.Name,
				Evidence:  map[string]any{"heap_used_percent": fixed(value), "heap_used_bytes": node.JVM.HeapUsedBytes, "heap_max_bytes": node.JVM.HeapMaxBytes, "single_snapshot": true},
				Threshold: thresholdText(threshold), Impact: "Sustained heap pressure increases garbage collection and node instability risk.",
				Recommendation: "Investigate query/indexing load, shard count, fielddata, circuit breakers, and heap sizing. Use a time series before concluding that memory is leaking.",
				Confidence:     healthmodel.ConfidenceHigh, RootCause: "jvm_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}

func garbageCollection() Checker {
	return newChecker("ES-JVM-002", "Garbage collection pressure", "JVM", "Uses baseline deltas to detect long old-generation collection pauses.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		if snapshot.Baseline == nil {
			return nil, skip("baseline_required_for_gc_rate")
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			previous, interval, ok := baselineNode(snapshot, node)
			if !ok {
				continue
			}
			count, countOK := counterDelta(node.JVM.OldGCCount, previous.OldGCCount)
			duration, durationOK := counterDelta(node.JVM.OldGCTimeMillis, previous.OldGCTimeMillis)
			if !countOK || !durationOK || count == 0 {
				continue
			}
			averagePause := float64(duration) / float64(count)
			severity := healthmodel.SeverityOK
			switch {
			case averagePause >= 5000:
				severity = healthmodel.SeverityCritical
			case averagePause >= 1000:
				severity = healthmodel.SeverityHigh
			case averagePause >= 500:
				severity = healthmodel.SeverityMedium
			}
			if severity == healthmodel.SeverityOK {
				continue
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Long old-generation garbage collection pauses", ResourceType: "node", Resource: node.Name,
				Evidence:  map[string]any{"old_gc_count_delta": count, "old_gc_time_delta_millis": duration, "average_pause_millis": fixed(averagePause), "interval_seconds": fixed(interval.Seconds())},
				Threshold: "average old GC pause >= 500ms", Impact: "Long stop-the-world pauses can cause request timeouts, node disconnects, and cluster instability.",
				Recommendation: "Correlate heap pressure with allocation rate, shard count, fielddata, query load, and GC logs.", Confidence: healthmodel.ConfidenceHigh, RootCause: "jvm_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}

func cpuHealth(threshold config.PercentThreshold) Checker {
	return newChecker("ES-CPU-001", "CPU and normalized load", "CPU", "Evaluates process/OS CPU and load normalized by available processors.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			cpu := math.Max(float64(node.CPU.ProcessPercent), float64(node.CPU.OSPercent))
			normalizedLoad := 0.0
			if node.AvailableProcessors > 0 {
				normalizedLoad = node.CPU.LoadAverage[0] / float64(node.AvailableProcessors)
			}
			severity := percentSeverity(cpu, threshold)
			if normalizedLoad >= 2 && healthmodel.SeverityRank(severity) < healthmodel.SeverityRank(healthmodel.SeverityCritical) {
				severity = healthmodel.SeverityCritical
			} else if normalizedLoad >= 1 && healthmodel.SeverityRank(severity) < healthmodel.SeverityRank(healthmodel.SeverityHigh) {
				severity = healthmodel.SeverityHigh
			} else if normalizedLoad >= 0.75 && healthmodel.SeverityRank(severity) < healthmodel.SeverityRank(healthmodel.SeverityMedium) {
				severity = healthmodel.SeverityMedium
			}
			if severity == healthmodel.SeverityOK {
				continue
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "High CPU or normalized load", ResourceType: "node", Resource: node.Name,
				Evidence:  map[string]any{"process_cpu_percent": node.CPU.ProcessPercent, "os_cpu_percent": node.CPU.OSPercent, "load_1m": fixed(node.CPU.LoadAverage[0]), "load_5m": fixed(node.CPU.LoadAverage[1]), "load_15m": fixed(node.CPU.LoadAverage[2]), "available_processors": node.AvailableProcessors, "normalized_load_1m": fixed(normalizedLoad), "single_snapshot": true},
				Threshold: thresholdText(threshold) + "; normalized load warning 0.75, high 1.0, critical 2.0", Impact: "CPU saturation raises search and indexing latency and can delay cluster coordination.",
				Recommendation: "Correlate the snapshot with sustained CPU, hot threads, query/indexing rates, merges, and thread-pool pressure.", Confidence: healthmodel.ConfidenceMedium, RootCause: "cpu_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}

func swapUsage() Checker {
	return newChecker("ES-MEM-001", "Swap usage", "Memory", "Detects Elasticsearch nodes using swap.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			if node.Memory.SwapUsed <= 0 {
				continue
			}
			severity := healthmodel.SeverityMedium
			ratio := percentage(node.Memory.SwapUsed, node.Memory.SwapTotal)
			if node.Memory.SwapUsed >= 1024*1024*1024 || ratio >= 25 {
				severity = healthmodel.SeverityHigh
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Elasticsearch node is using swap", ResourceType: "node", Resource: node.Name,
				Evidence: map[string]any{"swap_used_bytes": node.Memory.SwapUsed, "swap_total_bytes": node.Memory.SwapTotal, "swap_used_percent": fixed(ratio)}, Threshold: "0 bytes used",
				Impact: "Swapping introduces long and unpredictable JVM pauses.", Recommendation: "Follow Elasticsearch memory-lock and operating-system swappiness guidance; also verify that the host has sufficient RAM.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "memory_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}

func physicalMemory(threshold config.PercentThreshold) Checker {
	return newChecker("ES-MEM-002", "Physical memory utilization", "Memory", "Evaluates host memory conservatively because filesystem cache can make used RAM appear high.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			if node.Memory.TotalBytes <= 0 {
				continue
			}
			used := node.Memory.UsedBytes
			if used <= 0 {
				used = node.Memory.TotalBytes - node.Memory.FreeBytes
			}
			usedPercent := percentage(used, node.Memory.TotalBytes)
			if usedPercent < threshold.Warning {
				continue
			}
			severity := healthmodel.SeverityInfo
			if usedPercent >= threshold.High {
				severity = healthmodel.SeverityMedium
			}
			if usedPercent >= threshold.Critical {
				severity = healthmodel.SeverityHigh
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Host physical memory utilization is high", ResourceType: "node", Resource: node.Name,
				Evidence: map[string]any{"memory_used_percent": fixed(usedPercent), "memory_total_bytes": node.Memory.TotalBytes, "memory_used_bytes": used, "memory_free_bytes": node.Memory.FreeBytes, "swap_used_bytes": node.Memory.SwapUsed, "single_snapshot": true}, Threshold: thresholdText(threshold),
				Impact: "Sustained host-memory pressure can force swapping or invoke the operating-system out-of-memory killer, but Linux filesystem cache may make one used-memory snapshot look high.", Recommendation: "Correlate available memory, swap, JVM heap, cgroup limits, and operating-system pressure over time before changing heap or host sizing.",
				Confidence: healthmodel.ConfidenceMedium, RootCause: "memory_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}

func roleDistribution(profile config.HealthProfile) Checker {
	return newChecker("ES-NODE-002", "Node role redundancy", "Availability", "Evaluates master-eligible and data-role redundancy without requiring dedicated roles.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_info") {
			return nil, skip("node_info_unavailable")
		}
		if len(snapshot.Nodes) == 0 {
			return nil, skip("node_roles_unavailable")
		}
		counts := map[string]int{"master_eligible": 0, "data": 0, "ingest": 0, "ml": 0, "transform": 0, "remote_cluster_client": 0, "coordinating_only": 0}
		for _, node := range snapshot.Nodes {
			if len(node.Roles) == 0 {
				counts["coordinating_only"]++
			}
			dataCounted := false
			for _, role := range node.Roles {
				switch {
				case role == "master":
					counts["master_eligible"]++
				case role == "data" || strings.HasPrefix(role, "data_"):
					// A node with multiple tier roles remains one data node.
					if !dataCounted {
						counts["data"]++
						dataCounted = true
					}
				case role == "ingest", role == "ml", role == "transform", role == "remote_cluster_client":
					counts[role]++
				}
			}
		}
		severity := healthmodel.SeverityOK
		title := ""
		switch {
		case counts["master_eligible"] == 0:
			severity, title = healthmodel.SeverityCritical, "No master-eligible node was reported"
		case counts["data"] == 0:
			severity, title = healthmodel.SeverityCritical, "No data-role node was reported"
		case len(snapshot.Nodes) > 1 && counts["master_eligible"] == 1:
			severity, title = healthmodel.SeverityHigh, "Master-eligible role has no redundancy"
		case productionLike(profile) && len(snapshot.Nodes) > 1 && counts["master_eligible"] == 2:
			severity, title = healthmodel.SeverityMedium, "Two master-eligible nodes provide fragile quorum"
			if largeTopology(profile) {
				severity = healthmodel.SeverityHigh
			}
		case productionLike(profile) && len(snapshot.Nodes) > 1 && counts["data"] == 1:
			severity, title = healthmodel.SeverityHigh, "Data role has no node-level redundancy"
		}
		if severity == healthmodel.SeverityOK {
			return nil, nil
		}
		if !productionLike(profile) && severity != healthmodel.SeverityCritical {
			severity = healthmodel.SeverityInfo
		}
		return []healthmodel.Finding{{
			Severity: severity, Title: title, ResourceType: "cluster", Resource: snapshot.Cluster.Name,
			Evidence: map[string]any{"nodes": len(snapshot.Nodes), "role_counts": counts, "profile": profile}, Threshold: "production topology should preserve master quorum and data-node redundancy",
			Impact: "Loss of the only node carrying a required role can stop cluster coordination or make data unavailable.", Recommendation: "Place role-appropriate nodes across independent failure domains and use an odd-sized master-eligible voting topology where practical.",
			Confidence: healthmodel.ConfidenceHigh, RootCause: "topology_redundancy",
		}}, nil
	})
}

func fileDescriptors(threshold config.PercentThreshold) Checker {
	return newChecker("ES-NODE-001", "File descriptor utilization", "Node", "Compares open and maximum file descriptors per node.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			if node.MaxFileDescriptors <= 0 {
				continue
			}
			value := percentage(node.OpenFileDescriptors, node.MaxFileDescriptors)
			severity := percentSeverity(value, threshold)
			if severity == healthmodel.SeverityOK {
				continue
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "High file descriptor utilization", ResourceType: "node", Resource: node.Name,
				Evidence: map[string]any{"open_file_descriptors": node.OpenFileDescriptors, "max_file_descriptors": node.MaxFileDescriptors, "used_percent": fixed(value)}, Threshold: thresholdText(threshold),
				Impact: "Descriptor exhaustion prevents new files and network connections from being opened.", Recommendation: "Inspect connection/file growth and ensure the operating-system limit matches Elasticsearch production guidance.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "file_descriptor_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}

func diskHealth(threshold config.PercentThreshold) Checker {
	return newChecker("ES-DISK-001", "Disk watermark pressure", "Disk", "Uses effective cluster watermarks before fallback capacity thresholds.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		low, lowOK := snapshot.ClusterSettings.Effective("cluster.routing.allocation.disk.watermark.low")
		high, highOK := snapshot.ClusterSettings.Effective("cluster.routing.allocation.disk.watermark.high")
		flood, floodOK := snapshot.ClusterSettings.Effective("cluster.routing.allocation.disk.watermark.flood_stage")
		lowHeadroom, _ := snapshot.ClusterSettings.Effective("cluster.routing.allocation.disk.watermark.low.max_headroom")
		highHeadroom, _ := snapshot.ClusterSettings.Effective("cluster.routing.allocation.disk.watermark.high.max_headroom")
		floodHeadroom, _ := snapshot.ClusterSettings.Effective("cluster.routing.allocation.disk.watermark.flood_stage.max_headroom")
		configured := lowOK || highOK || floodOK
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			if !node.HasDataRole() || node.Filesystem.TotalBytes <= 0 {
				continue
			}
			used := node.Filesystem.UsedPercent()
			severity := healthmodel.SeverityOK
			thresholdDescription := thresholdText(threshold)
			if configured {
				thresholdDescription = fmt.Sprintf("effective low=%q (headroom %q), high=%q (headroom %q), flood_stage=%q (headroom %q)", low, lowHeadroom, high, highHeadroom, flood, floodHeadroom)
				switch {
				case floodOK && watermarkExceeded(node.Filesystem.TotalBytes, node.Filesystem.AvailableBytes, flood, floodHeadroom):
					severity = healthmodel.SeverityCritical
				case highOK && watermarkExceeded(node.Filesystem.TotalBytes, node.Filesystem.AvailableBytes, high, highHeadroom):
					severity = healthmodel.SeverityHigh
				case lowOK && watermarkExceeded(node.Filesystem.TotalBytes, node.Filesystem.AvailableBytes, low, lowHeadroom):
					severity = healthmodel.SeverityMedium
				}
			} else {
				severity = percentSeverity(used, threshold)
			}
			if severity == healthmodel.SeverityOK {
				continue
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Disk watermark or capacity threshold reached", ResourceType: "node", Resource: node.Name,
				Evidence: map[string]any{"used_percent": fixed(used), "total_bytes": node.Filesystem.TotalBytes, "available_bytes": node.Filesystem.AvailableBytes, "data_paths": node.Filesystem.DataPaths, "cluster_watermarks_used": configured}, Threshold: thresholdDescription,
				Impact: "Elasticsearch may restrict shard allocation and apply read-only blocks at flood stage.", Recommendation: "Increase available storage, reduce retained data, or rebalance shards while preserving recovery headroom.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "disk_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}

func diskImbalance(threshold config.VariationThreshold) Checker {
	return newChecker("ES-DISK-002", "Disk utilization imbalance", "Disk", "Compares disk utilization across data nodes.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		var values []float64
		var highest healthmodel.Node
		lowest := math.MaxFloat64
		for _, node := range snapshot.Nodes {
			if !node.HasDataRole() || node.Filesystem.TotalBytes <= 0 {
				continue
			}
			used := node.Filesystem.UsedPercent()
			values = append(values, used)
			if highest.Name == "" || used > highest.Filesystem.UsedPercent() {
				highest = node
			}
			if used < lowest {
				lowest = used
			}
		}
		if len(values) < 2 {
			return nil, nil
		}
		spread := highest.Filesystem.UsedPercent() - lowest
		if spread < threshold.Warning {
			return nil, nil
		}
		severity := healthmodel.SeverityMedium
		if spread >= threshold.High {
			severity = healthmodel.SeverityHigh
		}
		mean, median, deviation, coefficient := stats(values)
		return []healthmodel.Finding{{
			Severity: severity, Title: "Data-node disk usage is imbalanced", ResourceType: "cluster", Resource: snapshot.Cluster.Name,
			Evidence:  map[string]any{"highest_node": highest.Name, "highest_used_percent": fixed(highest.Filesystem.UsedPercent()), "lowest_used_percent": fixed(lowest), "spread_percentage_points": fixed(spread), "mean": mean, "median": median, "standard_deviation": deviation, "coefficient_of_variation": coefficient},
			Threshold: fmt.Sprintf("warning spread %.1f points, high %.1f points", threshold.Warning, threshold.High), Impact: "The fullest node can cross allocation watermarks while aggregate free space still appears sufficient.",
			Recommendation: "Inspect allocation filters, awareness rules, tier placement, and shard sizes; rebalance only after preserving failure-domain constraints.", Confidence: healthmodel.ConfidenceHigh, RootCause: "disk_imbalance",
		}}, nil
	})
}

func diskCapacityForecast(threshold config.PercentThreshold) Checker {
	return newChecker("ES-CAPACITY-001", "Disk capacity projection", "Capacity", "Projects the effective high watermark from two compatible filesystem samples without claiming a long-term trend.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		if snapshot.Baseline == nil {
			return nil, skip("baseline_required_for_capacity_projection")
		}
		high, configured := snapshot.ClusterSettings.Effective("cluster.routing.allocation.disk.watermark.high")
		headroom, _ := snapshot.ClusterSettings.Effective("cluster.routing.allocation.disk.watermark.high.max_headroom")
		if !configured {
			high = fmt.Sprintf("%g%%", threshold.High)
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			if !node.HasDataRole() || node.Filesystem.TotalBytes <= 0 {
				continue
			}
			previous, interval, ok := baselineNode(snapshot, node)
			if !ok || interval < 10*time.Minute || previous.DiskTotalBytes <= 0 || previous.DiskAvailableBytes <= 0 {
				continue
			}
			totalChange := math.Abs(float64(node.Filesystem.TotalBytes-previous.DiskTotalBytes)) / float64(node.Filesystem.TotalBytes)
			if totalChange > 0.05 {
				continue
			}
			consumed := previous.DiskAvailableBytes - node.Filesystem.AvailableBytes
			if consumed <= 0 {
				continue
			}
			requiredFree, valid := watermarkRequiredFree(node.Filesystem.TotalBytes, high, headroom)
			remaining := node.Filesystem.AvailableBytes - requiredFree
			if !valid || remaining <= 0 {
				continue
			}
			rate := float64(consumed) / interval.Seconds()
			if rate <= 0 {
				continue
			}
			secondsUntilHigh := float64(remaining) / rate
			if secondsUntilHigh <= 0 || secondsUntilHigh > (90*24*time.Hour).Seconds() {
				continue
			}
			untilHigh := time.Duration(secondsUntilHigh * float64(time.Second))
			severity := healthmodel.SeverityInfo
			switch {
			case untilHigh <= 24*time.Hour:
				severity = healthmodel.SeverityCritical
			case untilHigh <= 7*24*time.Hour:
				severity = healthmodel.SeverityHigh
			case untilHigh <= 30*24*time.Hour:
				severity = healthmodel.SeverityMedium
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Disk high watermark is approaching at the observed growth rate", ResourceType: "node", Resource: node.Name,
				Evidence: map[string]any{"baseline_interval_seconds": fixed(interval.Seconds()), "bytes_consumed_since_baseline": consumed, "observed_bytes_per_second": fixed(rate), "current_available_bytes": node.Filesystem.AvailableBytes, "required_free_bytes_at_high_watermark": requiredFree, "estimated_hours_to_high_watermark": fixed(untilHigh.Hours()), "effective_high_watermark": high, "effective_max_headroom": headroom}, Threshold: "two-snapshot projection: critical <= 1 day, high <= 7 days, medium <= 30 days, info <= 90 days",
				Impact: "If the sampled consumption rate persists, shard allocation can be restricted at the projected time.", Recommendation: "Validate the rate over a longer interval, retention schedule, and ingest cycle; add capacity or reduce retained data before the effective high watermark is reached.",
				Confidence: healthmodel.ConfidenceLow, RootCause: "disk_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}
