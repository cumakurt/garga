package checker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/config"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func indexHealth() Checker {
	return newChecker("ES-INDEX-001", "Index health", "Index", "Reports red and yellow user-index health separately from cluster status.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "indices") {
			return nil, skip("index_metrics_unavailable")
		}
		var findings []healthmodel.Finding
		for _, index := range snapshot.Indices {
			if index.System || strings.EqualFold(index.Health, "green") || index.Health == "" {
				continue
			}
			severity := healthmodel.SeverityMedium
			if strings.EqualFold(index.Health, "red") {
				severity = healthmodel.SeverityCritical
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Index health is " + strings.ToUpper(index.Health), ResourceType: "index", Resource: index.Name,
				Evidence: map[string]any{"health": index.Health, "status": index.Status, "primary_shards": index.PrimaryShards, "replicas": index.Replicas, "store_bytes": index.StoreBytes}, Threshold: "GREEN",
				Impact: "Red indices can have unavailable data; yellow indices have reduced shard redundancy.", Recommendation: "Resolve node, allocation, disk, and replica constraints associated with this index.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "cluster_availability",
			})
			if len(findings) >= 20 {
				break
			}
		}
		return findings, nil
	})
}

func zeroReplicas(profile config.HealthProfile) Checker {
	return newChecker("ES-INDEX-002", "Replica availability", "Availability", "Evaluates replica=0 with topology, profile, system-index, and data-stream context.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "indices") {
			return nil, skip("index_metrics_unavailable")
		}
		var findings []healthmodel.Finding
		for _, index := range snapshot.Indices {
			if index.System || index.Replicas != 0 || strings.EqualFold(index.Status, "close") {
				continue
			}
			severity := healthmodel.SeverityMedium
			if snapshot.Cluster.Nodes == 1 || availabilityLenient(profile) {
				severity = healthmodel.SeverityInfo
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Index has no replica shards", ResourceType: "index", Resource: index.Name,
				Evidence: map[string]any{"replicas": 0, "primary_shards": index.PrimaryShards, "cluster_nodes": snapshot.Cluster.Nodes, "data_stream": index.DataStream, "profile": profile}, Threshold: "at least one replica for production data",
				Impact: "A node loss can make the affected primary shard unavailable until recovery; no replica copy exists in the cluster.", Recommendation: "For production data, configure replicas after ensuring enough nodes and failure domains. Replica=0 may be intentional in single-node development.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "no_redundancy:" + index.Name,
			})
			if len(findings) >= 50 {
				break
			}
		}
		return findings, nil
	})
}

func deletedDocuments(threshold config.RatioThreshold) Checker {
	return newChecker("ES-INDEX-003", "Deleted document ratio", "Index", "Detects high deleted-document ratios without prescribing force merge for active indices.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "indices") {
			return nil, skip("index_metrics_unavailable")
		}
		var findings []healthmodel.Finding
		for _, index := range snapshot.Indices {
			total := index.Documents + index.DeletedDocuments
			if index.System || total < 10_000 {
				continue
			}
			ratio := index.DeletedRatio()
			if ratio < threshold.Warning {
				continue
			}
			severity := healthmodel.SeverityMedium
			if ratio >= threshold.High {
				severity = healthmodel.SeverityHigh
			}
			active := index.DataStream != "" || !strings.EqualFold(strings.TrimSpace(index.Settings["index.blocks.write"]), "true")
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "High deleted-document ratio", ResourceType: "index", Resource: index.Name,
				Evidence: map[string]any{"documents": index.Documents, "deleted_documents": index.DeletedDocuments, "deleted_ratio": fixed(ratio), "possibly_active": active, "data_stream": index.DataStream}, Threshold: fmt.Sprintf("warning %.0f%%, high %.0f%%", threshold.Warning*100, threshold.High*100),
				Impact: "Deleted Lucene documents retain disk and can increase merge and search work until normal merges reclaim them.", Recommendation: "Review update/delete patterns and merge pressure. Do not force-merge an actively written index; use lifecycle and rollover for immutable data.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "delete_churn:" + index.Name,
			})
			if len(findings) >= 20 {
				break
			}
		}
		return findings, nil
	})
}

func emptyIndices() Checker {
	return newChecker("ES-INDEX-004", "Empty indices", "Index", "Finds old empty user indices while suppressing system and data-stream rollover destinations.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "indices") {
			return nil, skip("index_metrics_unavailable")
		}
		var names []string
		for _, index := range snapshot.Indices {
			if index.System || index.DataStream != "" || index.Documents != 0 || index.DeletedDocuments != 0 || strings.EqualFold(index.Status, "close") {
				continue
			}
			if index.CreationTime.IsZero() || snapshot.Timestamp.Sub(index.CreationTime) < 7*24*time.Hour {
				continue
			}
			names = append(names, index.Name)
		}
		if len(names) == 0 {
			return nil, nil
		}
		if len(names) > 20 {
			names = names[:20]
		}
		return []healthmodel.Finding{{
			Severity: healthmodel.SeverityLow, Title: "Old empty user indices were found", ResourceType: "cluster", Resource: snapshot.Cluster.Name,
			Evidence: map[string]any{"example_indices": names, "reported_examples": len(names)}, Threshold: "0 documents and older than 7 days",
			Impact: "Empty indices still consume cluster-state and shard resources.", Recommendation: "Confirm ownership and lifecycle intent before deleting or preventing future creation. System indices and data-stream backing indices are excluded.",
			Confidence: healthmodel.ConfidenceMedium, RootCause: "unused_indices",
		}}, nil
	})
}

func oldIndices() Checker {
	return newChecker("ES-INDEX-005", "Lifecycle candidates", "Capacity", "Identifies old, sizeable user indices as lifecycle review candidates.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "indices") {
			return nil, skip("index_metrics_unavailable")
		}
		var findings []healthmodel.Finding
		for _, index := range snapshot.Indices {
			if index.System || index.CreationTime.IsZero() || index.StoreBytes < 5*1024*1024*1024 || snapshot.Timestamp.Sub(index.CreationTime) < 90*24*time.Hour {
				continue
			}
			findings = append(findings, healthmodel.Finding{
				Severity: healthmodel.SeverityLow, Title: "Old large index is a lifecycle candidate", ResourceType: "index", Resource: index.Name,
				Evidence: map[string]any{"age_days": int(snapshot.Timestamp.Sub(index.CreationTime).Hours() / 24), "store_bytes": index.StoreBytes, "ilm_policy": index.ILMPolicy, "data_stream": index.DataStream}, Threshold: "older than 90 days and larger than 5 GiB",
				Impact: "Long-lived data can consume capacity beyond business retention requirements.", Recommendation: "Validate retention requirements and consider an ILM/data-stream lifecycle. Do not delete data solely from this heuristic.",
				Confidence: healthmodel.ConfidenceMedium, RootCause: "retention_capacity:" + index.Name,
			})
			if len(findings) >= 20 {
				break
			}
		}
		return findings, nil
	})
}

func indexBlocks() Checker {
	return newChecker("ES-INDEX-006", "Index write blocks", "Reliability", "Detects flood-stage read-only blocks and other explicit write blocks.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "index_settings") {
			return nil, skip("index_settings_unavailable")
		}
		var findings []healthmodel.Finding
		for _, index := range snapshot.Indices {
			readOnlyDelete := strings.EqualFold(index.Settings["index.blocks.read_only_allow_delete"], "true")
			writeBlock := strings.EqualFold(index.Settings["index.blocks.write"], "true")
			readOnly := strings.EqualFold(index.Settings["index.blocks.read_only"], "true")
			if !readOnlyDelete && !writeBlock && !readOnly {
				continue
			}
			severity := healthmodel.SeverityHigh
			rootCause := "index_write_block:" + index.Name
			if readOnlyDelete {
				severity = healthmodel.SeverityCritical
				rootCause = "disk_allocation_pressure"
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Index is blocked for writes", ResourceType: "index", Resource: index.Name,
				Evidence: map[string]any{"read_only_allow_delete": readOnlyDelete, "read_only": readOnly, "write_block": writeBlock}, Threshold: "no unexpected write block",
				Impact: "Applications cannot write to the index. read_only_allow_delete commonly indicates flood-stage disk pressure.", Recommendation: "Resolve disk pressure or the operational reason first, then remove the block through an explicitly authorized change process; the health check will not change settings.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: rootCause,
			})
			if len(findings) >= 50 {
				break
			}
		}
		return findings, nil
	})
}
