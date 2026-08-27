package checker

import (
	"context"
	"fmt"

	"github.com/cumakurt/garga/internal/config"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

var importantThreadPools = map[string]struct{}{
	"search": {}, "search_coordination": {}, "write": {}, "get": {}, "analyze": {}, "management": {},
	"snapshot": {}, "refresh": {}, "flush": {}, "force_merge": {}, "system_write": {}, "system_read": {},
}

func threadPools(queueHigh int) Checker {
	return newChecker("ES-THREADPOOL-001", "Thread-pool pressure", "ThreadPool", "Evaluates current queues and baseline-normalized rejection deltas.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			previous, interval, hasBaseline := baselineNode(snapshot, node)
			cumulative := make(map[string]int64)
			for name, pool := range node.ThreadPools {
				if _, important := importantThreadPools[name]; !important {
					continue
				}
				if pool.Queue > 0 {
					severity := healthmodel.SeverityMedium
					if pool.Queue >= queueHigh {
						severity = healthmodel.SeverityHigh
					}
					findings = append(findings, healthmodel.Finding{
						Severity: severity, Title: "Thread-pool queue is building", ResourceType: "thread_pool", Resource: node.Name + "/" + name,
						Evidence: map[string]any{"active": pool.Active, "threads": pool.Threads, "queue": pool.Queue, "rejected_total": pool.Rejected, "completed_total": pool.Completed}, Threshold: fmt.Sprintf("queue high at %d", queueHigh),
						Impact: "A sustained queue increases request latency and can lead to rejections.", Recommendation: "Identify the workload causing saturation and correlate it with CPU, heap, disk, shard, search, and indexing pressure.",
						Confidence: healthmodel.ConfidenceMedium, RootCause: "thread_pool_pressure:" + node.ID + ":" + name,
					})
				}
				if hasBaseline {
					delta, ok := counterDelta(pool.Rejected, previous.ThreadPoolRejected[name])
					if ok && delta > 0 {
						rate := float64(delta) / interval.Seconds()
						severity := healthmodel.SeverityMedium
						if rate >= 1 {
							severity = healthmodel.SeverityHigh
						}
						findings = append(findings, healthmodel.Finding{
							Severity: severity, Title: "Thread-pool rejections increased", ResourceType: "thread_pool", Resource: node.Name + "/" + name,
							Evidence: map[string]any{"rejected_delta": delta, "rejections_per_second": fixed(rate), "interval_seconds": fixed(interval.Seconds()), "rejected_total": pool.Rejected}, Threshold: "0 new rejections",
							Impact: "Rejected operations fail or require client retries and are direct evidence of workload pressure.", Recommendation: "Reduce the producing workload or resolve the constrained CPU, memory, disk, or shard architecture; do not only enlarge queues.",
							Confidence: healthmodel.ConfidenceHigh, RootCause: "thread_pool_pressure:" + node.ID + ":" + name,
						})
					}
				} else if pool.Rejected > 0 {
					cumulative[name] = pool.Rejected
				}
			}
			if !hasBaseline && len(cumulative) > 0 {
				findings = append(findings, healthmodel.Finding{
					Severity: healthmodel.SeverityInfo, Title: "Thread-pool rejection counters are non-zero", ResourceType: "node", Resource: node.Name,
					Evidence: map[string]any{"cumulative_rejections": cumulative, "counter_scope": "node lifetime since last restart", "baseline_available": false}, Threshold: "informational without a baseline",
					Impact: "The counters prove historical rejection but not current pressure.", Recommendation: "Save a baseline and compare a later snapshot to calculate rejection deltas and rates.",
					Confidence: healthmodel.ConfidenceHigh, RootCause: "historical_thread_pool_rejections:" + node.ID,
				})
			}
		}
		return findings, nil
	})
}

func circuitBreakers() Checker {
	return newChecker("ES-BREAKER-001", "Circuit breaker pressure", "CircuitBreaker", "Evaluates breaker utilization and trip deltas.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			previous, interval, hasBaseline := baselineNode(snapshot, node)
			for name, breaker := range node.Breakers {
				used := percentage(breaker.EstimatedBytes, breaker.LimitBytes)
				severity := healthmodel.SeverityOK
				if used >= 95 {
					severity = healthmodel.SeverityHigh
				} else if used >= 80 {
					severity = healthmodel.SeverityMedium
				}
				tripDelta := int64(0)
				if hasBaseline {
					tripDelta, _ = counterDelta(breaker.Tripped, previous.BreakerTrips[name])
					if tripDelta > 0 && healthmodel.SeverityRank(severity) < healthmodel.SeverityRank(healthmodel.SeverityHigh) {
						severity = healthmodel.SeverityHigh
					}
				} else if breaker.Tripped > 0 && severity == healthmodel.SeverityOK {
					severity = healthmodel.SeverityInfo
				}
				if severity == healthmodel.SeverityOK {
					continue
				}
				evidence := map[string]any{"estimated_bytes": breaker.EstimatedBytes, "limit_bytes": breaker.LimitBytes, "used_percent": fixed(used), "tripped_total": breaker.Tripped, "counter_scope": "cumulative"}
				if hasBaseline {
					evidence["tripped_delta"] = tripDelta
					evidence["interval_seconds"] = fixed(interval.Seconds())
				}
				findings = append(findings, healthmodel.Finding{
					Severity: severity, Title: "Circuit breaker pressure detected", ResourceType: "circuit_breaker", Resource: node.Name + "/" + name, Evidence: evidence, Threshold: "warning 80%, high 95%, or any new trip",
					Impact: "Circuit breaker trips reject operations to protect the JVM from out-of-memory failure.", Recommendation: "Identify the request, fielddata, in-flight, accounting, or parent breaker source and reduce the responsible memory demand.",
					Confidence: healthmodel.ConfidenceHigh, RootCause: "memory_pressure:" + node.ID,
				})
			}
		}
		return findings, nil
	})
}

func indexingPressure() Checker {
	return newChecker("ES-INDEXING-001", "Indexing pressure", "Indexing", "Evaluates current indexing memory and baseline-normalized rejections.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			pressure := node.IndexingPressure
			current := pressure.CoordinatingBytes + pressure.PrimaryBytes + pressure.ReplicaBytes
			used := percentage(current, pressure.MemoryLimitBytes)
			rejections := pressure.CoordinatingRejections + pressure.PrimaryRejections + pressure.ReplicaRejections
			severity := healthmodel.SeverityOK
			if used >= 95 {
				severity = healthmodel.SeverityHigh
			} else if used >= 80 {
				severity = healthmodel.SeverityMedium
			}
			previous, interval, hasBaseline := baselineNode(snapshot, node)
			delta := int64(0)
			if hasBaseline {
				delta, _ = counterDelta(rejections, previous.IndexingPressureRejections)
				if delta > 0 {
					severity = healthmodel.SeverityHigh
				}
			} else if rejections > 0 && severity == healthmodel.SeverityOK {
				severity = healthmodel.SeverityInfo
			}
			if severity == healthmodel.SeverityOK {
				continue
			}
			evidence := map[string]any{"current_bytes": current, "memory_limit_bytes": pressure.MemoryLimitBytes, "used_percent": fixed(used), "rejections_total": rejections, "counter_scope": "cumulative"}
			if hasBaseline {
				evidence["rejections_delta"] = delta
				evidence["interval_seconds"] = fixed(interval.Seconds())
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Indexing pressure or rejections detected", ResourceType: "node", Resource: node.Name, Evidence: evidence, Threshold: "warning 80%, high 95%, or any new rejection",
				Impact: "Write operations may be rejected or delayed to protect node memory.", Recommendation: "Reduce bulk concurrency/size, balance ingest load, and investigate downstream disk, merge, shard, and JVM pressure.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "indexing_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}

func performance() Checker {
	return newChecker("ES-PERF-001", "Search and indexing performance counters", "Performance", "Uses deltas when available and labels lifetime counters explicitly.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			previous, interval, hasBaseline := baselineNode(snapshot, node)
			queryCount, queryTime := node.Indices.QueryTotal, node.Indices.QueryTimeMillis
			indexFailures := node.Indices.IndexFailed
			fielddataEvictions := node.Indices.FielddataEvictions
			queryCacheEvictions := node.Indices.QueryCacheEvictions
			requestCacheEvictions := node.Indices.RequestCacheEvictions
			counterScope := "node lifetime since last restart"
			if hasBaseline {
				queryCount, _ = counterDelta(queryCount, previous.QueryTotal)
				queryTime, _ = counterDelta(queryTime, previous.QueryTimeMillis)
				indexFailures, _ = counterDelta(indexFailures, previous.IndexFailed)
				fielddataEvictions, _ = counterDelta(fielddataEvictions, previous.FielddataEvictions)
				queryCacheEvictions, _ = counterDelta(queryCacheEvictions, previous.QueryCacheEvictions)
				requestCacheEvictions, _ = counterDelta(requestCacheEvictions, previous.RequestCacheEvictions)
				counterScope = "baseline interval"
			}
			averageQueryMillis := 0.0
			if queryCount > 0 {
				averageQueryMillis = float64(queryTime) / float64(queryCount)
			}
			severity := healthmodel.SeverityOK
			title := ""
			switch {
			case hasBaseline && indexFailures > 0:
				severity, title = healthmodel.SeverityHigh, "Indexing failures increased"
			case hasBaseline && fielddataEvictions > 0:
				severity, title = healthmodel.SeverityMedium, "Fielddata evictions increased"
			case averageQueryMillis >= 1000:
				severity, title = healthmodel.SeverityMedium, "Average query phase latency is high"
			case !hasBaseline && (indexFailures > 0 || fielddataEvictions > 0):
				severity, title = healthmodel.SeverityInfo, "Cumulative performance counters are non-zero"
			}
			if severity == healthmodel.SeverityOK {
				continue
			}
			evidence := map[string]any{"average_query_millis": fixed(averageQueryMillis), "query_count": queryCount, "index_failures": indexFailures, "fielddata_evictions": fielddataEvictions, "query_cache_evictions": queryCacheEvictions, "request_cache_evictions": requestCacheEvictions, "counter_scope": counterScope}
			if hasBaseline {
				evidence["interval_seconds"] = fixed(interval.Seconds())
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: title, ResourceType: "node", Resource: node.Name, Evidence: evidence, Threshold: "no new failures/evictions; query latency is workload-dependent",
				Impact: "Failed writes lose work unless clients retry; fielddata churn and slow queries consume heap and increase latency.", Recommendation: "Correlate deltas with workload, slow logs, mappings, shard fan-out, caches, and resource pressure. Do not tune cache hit ratios in isolation.",
				Confidence: healthmodel.ConfidenceMedium, RootCause: "workload_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}

func mergeAndRefreshPressure(profile config.HealthProfile) Checker {
	return newChecker("ES-PERF-002", "Merge and refresh pressure", "Performance", "Uses baseline deltas for merge throttling and refresh activity and labels lifetime counters explicitly.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") {
			return nil, skip("node_stats_unavailable")
		}
		throttleWarning, throttleHigh, refreshLatency := 20.0, 50.0, 500.0
		if searchSensitive(profile) {
			throttleWarning, throttleHigh, refreshLatency = 10.0, 35.0, 250.0
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			previous, interval, hasBaseline := baselineNode(snapshot, node)
			if !hasBaseline {
				if node.Indices.MergeThrottledTimeMillis <= 0 {
					continue
				}
				findings = append(findings, healthmodel.Finding{
					Severity: healthmodel.SeverityInfo, Title: "Merge throttling has occurred during the node lifetime", ResourceType: "node", Resource: node.Name,
					Evidence: map[string]any{"merge_throttled_time_millis_total": node.Indices.MergeThrottledTimeMillis, "merge_total": node.Indices.MergeTotal, "counter_scope": "node lifetime since last restart", "baseline_available": false}, Threshold: "informational without a baseline",
					Impact: "Historical throttling proves that indexing was constrained at some point but does not prove current pressure.", Recommendation: "Save a baseline and compare a later snapshot to measure the current throttle ratio and correlate it with disk and indexing load.",
					Confidence: healthmodel.ConfidenceHigh, RootCause: "historical_merge_pressure:" + node.ID,
				})
				continue
			}
			mergeDelta, mergeOK := counterDelta(node.Indices.MergeTotal, previous.MergeTotal)
			throttledDelta, throttleOK := counterDelta(node.Indices.MergeThrottledTimeMillis, previous.MergeThrottledTimeMillis)
			refreshDelta, refreshOK := counterDelta(node.Indices.RefreshTotal, previous.RefreshTotal)
			refreshTimeDelta, refreshTimeOK := counterDelta(node.Indices.RefreshTimeMillis, previous.RefreshTimeMillis)
			if !mergeOK || !throttleOK || !refreshOK || !refreshTimeOK || interval.Milliseconds() <= 0 {
				continue
			}
			throttlePercent := float64(throttledDelta) / float64(interval.Milliseconds()) * 100
			refreshRate := float64(refreshDelta) / interval.Seconds()
			averageRefreshMillis := 0.0
			if refreshDelta > 0 {
				averageRefreshMillis = float64(refreshTimeDelta) / float64(refreshDelta)
			}
			refreshRateThreshold := 10.0
			if node.AvailableProcessors > 0 && float64(node.AvailableProcessors*5) > refreshRateThreshold {
				refreshRateThreshold = float64(node.AvailableProcessors * 5)
			}
			severity := healthmodel.SeverityOK
			title := ""
			switch {
			case throttlePercent >= throttleHigh:
				severity, title = healthmodel.SeverityHigh, "Merge throttling consumed a large share of the baseline interval"
			case throttlePercent >= throttleWarning:
				severity, title = healthmodel.SeverityMedium, "Merge throttling is sustained"
			case averageRefreshMillis >= refreshLatency:
				severity, title = healthmodel.SeverityMedium, "Refresh operations are slow"
			case refreshRate >= refreshRateThreshold:
				severity, title = healthmodel.SeverityMedium, "Refresh activity is high for node capacity"
			}
			if severity == healthmodel.SeverityOK {
				continue
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: title, ResourceType: "node", Resource: node.Name,
				Evidence: map[string]any{"interval_seconds": fixed(interval.Seconds()), "merge_delta": mergeDelta, "merge_throttled_millis_delta": throttledDelta, "merge_throttled_interval_percent": fixed(throttlePercent), "refresh_delta": refreshDelta, "refreshes_per_second": fixed(refreshRate), "average_refresh_millis": fixed(averageRefreshMillis), "refresh_rate_heuristic": fixed(refreshRateThreshold), "profile": profile}, Threshold: fmt.Sprintf("merge throttle warning %.0f%%/high %.0f%% of interval; refresh latency >= %.0fms or contextual refresh-rate heuristic", throttleWarning, throttleHigh, refreshLatency),
				Impact: "Sustained merge throttling limits indexing throughput; excessive or slow refreshes increase disk I/O, CPU, and segment churn.", Recommendation: "Correlate disk latency, indexing rate, refresh intervals, shard size, and merge backlog. Adjust lifecycle or workload behavior before changing low-level merge settings.",
				Confidence: healthmodel.ConfidenceMedium, RootCause: "workload_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}

func segments(profile config.HealthProfile) Checker {
	return newChecker("ES-SEGMENT-001", "Segment density", "Index", "Normalizes segment count by shards assigned to each node.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "nodes_stats") || !collectionSucceeded(snapshot, "shards") {
			return nil, skip("node_or_shard_metrics_unavailable")
		}
		warning, high := 500.0, 1000.0
		if searchSensitive(profile) {
			warning, high = 300.0, 600.0
		}
		shardsByNode := make(map[string]int64)
		for _, shard := range snapshot.Shards {
			if shard.Node != "" && shard.State == "STARTED" {
				shardsByNode[shard.Node]++
			}
		}
		var findings []healthmodel.Finding
		for _, node := range snapshot.Nodes {
			shards := shardsByNode[node.Name]
			if shards == 0 || node.Indices.SegmentCount == 0 {
				continue
			}
			perShard := float64(node.Indices.SegmentCount) / float64(shards)
			severity := healthmodel.SeverityOK
			if perShard >= high {
				severity = healthmodel.SeverityHigh
			} else if perShard >= warning {
				severity = healthmodel.SeverityMedium
			}
			if severity == healthmodel.SeverityOK {
				continue
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "High segment density", ResourceType: "node", Resource: node.Name,
				Evidence: map[string]any{"segments": node.Indices.SegmentCount, "assigned_started_shards": shards, "segments_per_shard": fixed(perShard), "segment_memory_bytes": node.Indices.SegmentMemoryBytes, "profile": profile}, Threshold: fmt.Sprintf("heuristic warning %.0f, high %.0f segments per shard", warning, high),
				Impact: "Excessive segments increase heap metadata, file descriptors, and search overhead.", Recommendation: "Review refresh rate, merge pressure, shard sizing, and indexing patterns. Thresholds are workload-dependent.",
				Confidence: healthmodel.ConfidenceMedium, RootCause: "segment_pressure:" + node.ID,
			})
		}
		return findings, nil
	})
}
