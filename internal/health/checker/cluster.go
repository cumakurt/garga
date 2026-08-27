package checker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/config"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func clusterStatus() Checker {
	return newChecker("ES-CLUSTER-001", "Cluster health status", "Cluster", "Evaluates cluster status together with shard availability.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		status := strings.ToLower(snapshot.ClusterHealth.Status)
		if status == "" {
			return nil, skip("cluster_health_unavailable")
		}
		var severity healthmodel.Severity
		switch status {
		case "green":
			return nil, nil
		case "yellow":
			severity = healthmodel.SeverityMedium
		case "red":
			severity = healthmodel.SeverityCritical
		default:
			severity = healthmodel.SeverityHigh
		}
		return []healthmodel.Finding{{
			Severity: severity, Title: "Elasticsearch cluster health is " + strings.ToUpper(status), ResourceType: "cluster", Resource: snapshot.Cluster.Name,
			Evidence:  map[string]any{"status": status, "active_primary_shards": snapshot.ClusterHealth.ActivePrimaryShards, "active_shards": snapshot.ClusterHealth.ActiveShards, "unassigned_shards": snapshot.ClusterHealth.UnassignedShards, "active_shards_percent": fixed(snapshot.ClusterHealth.ActiveShardsPercentAsNumber)},
			Threshold: "GREEN", Impact: "Unavailable primary shards can make data inaccessible; unavailable replicas reduce redundancy.",
			Recommendation: "Resolve the underlying allocation or node failure before treating the cluster as healthy.", Confidence: healthmodel.ConfidenceHigh, RootCause: "cluster_availability",
		}}, nil
	})
}

func pendingTasks(cfg config.HealthConfig) Checker {
	return newChecker("ES-CLUSTER-002", "Pending cluster tasks", "Cluster", "Detects cluster-manager tasks waiting unusually long.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "pending_tasks") {
			return nil, skip("pending_tasks_unavailable")
		}
		var longest healthmodel.PendingTask
		for _, task := range snapshot.PendingTasks {
			if task.QueueMillis > longest.QueueMillis {
				longest = task
			}
		}
		if longest.QueueMillis < cfg.Thresholds.PendingTaskWarning.Milliseconds() && snapshot.ClusterHealth.MaxTaskWaitMillis < cfg.Thresholds.PendingTaskWarning.Milliseconds() {
			return nil, nil
		}
		observed := longest.QueueMillis
		if snapshot.ClusterHealth.MaxTaskWaitMillis > observed {
			observed = snapshot.ClusterHealth.MaxTaskWaitMillis
		}
		severity := healthmodel.SeverityMedium
		if observed >= cfg.Thresholds.PendingTaskHigh.Milliseconds() {
			severity = healthmodel.SeverityHigh
		}
		return []healthmodel.Finding{{
			Severity: severity, Title: "Cluster tasks are waiting in the management queue", ResourceType: "cluster", Resource: snapshot.Cluster.Name,
			Evidence:       map[string]any{"pending_tasks": len(snapshot.PendingTasks), "longest_queue_millis": observed, "priority": longest.Priority, "source": longest.Source, "executing": longest.Executing},
			Threshold:      fmt.Sprintf("warning %s, high %s", cfg.Thresholds.PendingTaskWarning, cfg.Thresholds.PendingTaskHigh),
			Impact:         "Delayed cluster-state updates can block allocation, mappings, index operations, and recovery.",
			Recommendation: "Inspect the longest pending task and cluster-manager node load; remove the source of sustained cluster-state contention.", Confidence: healthmodel.ConfidenceHigh, RootCause: "cluster_management_backlog",
		}}, nil
	})
}

func singleNode(profile config.HealthProfile) Checker {
	return newChecker("ES-AVAIL-001", "Node-level redundancy", "Availability", "Detects clusters with no node-level redundancy.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if snapshot.Cluster.Nodes != 1 {
			return nil, nil
		}
		severity := healthmodel.SeverityMedium
		if availabilityLenient(profile) {
			severity = healthmodel.SeverityInfo
		}
		return []healthmodel.Finding{{
			Severity: severity, Title: "Single-node cluster has no node-level redundancy", ResourceType: "cluster", Resource: snapshot.Cluster.Name,
			Evidence: map[string]any{"number_of_nodes": 1, "profile": profile}, Threshold: "more than one node for node-level redundancy",
			Impact: "A node or host failure makes the entire cluster unavailable.", Recommendation: "For production workloads, deploy additional role-appropriate nodes across independent failure domains. A single node may be intentional in development.",
			Confidence: healthmodel.ConfidenceHigh, RootCause: "topology_redundancy",
		}}, nil
	})
}

func unassignedShards() Checker {
	return newChecker("ES-SHARD-001", "Unassigned shards", "Shard", "Explains unavailable primary and replica shards.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "cluster_health") {
			return nil, skip("cluster_health_unavailable")
		}
		if snapshot.ClusterHealth.UnassignedShards == 0 {
			return nil, nil
		}
		primaryCount := 0
		reasons := make(map[string]int)
		for _, shard := range snapshot.Shards {
			if shard.State != "UNASSIGNED" {
				continue
			}
			if shard.Primary {
				primaryCount++
			}
			reason := shard.UnassignedReason
			if reason == "" {
				reason = "UNKNOWN"
			}
			reasons[reason]++
		}
		severity := healthmodel.SeverityHigh
		if primaryCount > 0 || strings.EqualFold(snapshot.ClusterHealth.Status, "red") {
			severity = healthmodel.SeverityCritical
		}
		evidence := map[string]any{"unassigned_shards": snapshot.ClusterHealth.UnassignedShards, "unassigned_primaries": primaryCount, "reasons": reasons, "delayed_unassigned_shards": snapshot.ClusterHealth.DelayedUnassignedShards}
		rootCause := "unassigned_shards"
		if snapshot.Allocation != nil {
			evidence["example_index"] = snapshot.Allocation.Index
			evidence["example_shard"] = snapshot.Allocation.Shard
			evidence["example_primary"] = snapshot.Allocation.Primary
			evidence["allocation_reason"] = snapshot.Allocation.Reason
			evidence["failed_allocation_count"] = snapshot.Allocation.FailedAllocationCount
			evidence["last_allocation_status"] = snapshot.Allocation.LastAllocationStatus
			for _, node := range snapshot.Allocation.CandidateNodes {
				if strings.Contains(strings.ToLower(node.Deciders), "disk") {
					rootCause = "disk_allocation_pressure"
					break
				}
			}
		}
		return []healthmodel.Finding{{
			Severity: severity, Title: "Cluster has unassigned shards", ResourceType: "cluster", Resource: snapshot.Cluster.Name, Evidence: evidence,
			Threshold: "0 unassigned shards", Impact: "Primary shards can make data unavailable; replica shards reduce fault tolerance.",
			Recommendation: "Use the allocation explanation and node/disk findings to resolve the allocation decider blocking these shards.", Confidence: healthmodel.ConfidenceHigh, RootCause: rootCause,
		}}, nil
	})
}

func longTasks(warning time.Duration) Checker {
	return newChecker("ES-TASK-001", "Long-running tasks", "Performance", "Detects expensive long-running Elasticsearch operations in deep mode.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "tasks") {
			return nil, skip("deep_task_collection_unavailable")
		}
		var findings []healthmodel.Finding
		for _, task := range snapshot.Tasks {
			if time.Duration(task.RunningNanos) < warning {
				continue
			}
			kind, resourceIntensive := taskKind(task.Action)
			severity := healthmodel.SeverityInfo
			title := "Long-running Elasticsearch background task"
			if resourceIntensive {
				severity = healthmodel.SeverityMedium
				title = "Long-running " + kind + " task"
			}
			if resourceIntensive && time.Duration(task.RunningNanos) >= 4*warning {
				severity = healthmodel.SeverityHigh
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: title, ResourceType: "task", Resource: fmt.Sprintf("%s:%d", task.Node, task.ID),
				Evidence: map[string]any{"action": task.Action, "type": task.Type, "description": task.Description, "task_kind": kind, "resource_intensive": resourceIntensive, "running_seconds": fixed(float64(task.RunningNanos) / float64(time.Second))}, Threshold: warning.String(),
				Impact: "Long-running reindex, update/delete-by-query, snapshot, restore, or other background tasks can consume cluster resources.", Recommendation: "Confirm that the operation is expected and inspect its progress and resource pressure before considering cancellation.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "long_running_task:" + task.Action,
			})
			if len(findings) >= 20 {
				break
			}
		}
		return findings, nil
	})
}

func taskKind(action string) (string, bool) {
	normalized := strings.ToLower(action)
	for _, candidate := range []struct {
		fragment string
		name     string
	}{
		{"reindex", "reindex"},
		{"update/byquery", "update-by-query"},
		{"delete/byquery", "delete-by-query"},
		{"snapshot", "snapshot"},
		{"restore", "restore"},
	} {
		if strings.Contains(normalized, candidate.fragment) {
			return candidate.name, true
		}
	}
	return "other", false
}
