package checker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/config"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func ilmHealth() Checker {
	return newChecker("ES-ILM-001", "Index lifecycle management", "ILM", "Detects ILM execution errors and unmanaged user indices in deep mode.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "ilm") {
			return nil, skip("deep_ilm_collection_unavailable")
		}
		var findings []healthmodel.Finding
		managed := make(map[string]bool, len(snapshot.ILM.Indices))
		for _, index := range snapshot.ILM.Indices {
			managed[index.Index] = index.Managed
			if index.FailedStep == "" && !strings.EqualFold(index.Step, "ERROR") {
				continue
			}
			findings = append(findings, healthmodel.Finding{
				Severity: healthmodel.SeverityHigh, Title: "ILM policy execution is in an error step", ResourceType: "index", Resource: index.Index,
				Evidence: map[string]any{"policy": index.Policy, "phase": index.Phase, "action": index.Action, "step": index.Step, "failed_step": index.FailedStep, "step_info": index.StepInfo}, Threshold: "no ILM error step",
				Impact: "Rollover, retention, tier migration, or deletion may not occur as expected.", Recommendation: "Investigate the failed ILM step and its prerequisite; retry or change policy only through an authorized operational workflow.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "ilm_error:" + index.Index,
			})
		}
		unmanaged := 0
		var examples []string
		for _, index := range snapshot.Indices {
			if index.System || index.DataStream != "" || index.StoreBytes == 0 || managed[index.Name] || index.ILMPolicy != "" {
				continue
			}
			unmanaged++
			if len(examples) < 20 {
				examples = append(examples, index.Name)
			}
		}
		if unmanaged > 0 {
			findings = append(findings, healthmodel.Finding{
				Severity: healthmodel.SeverityLow, Title: "User indices are not managed by ILM", ResourceType: "cluster", Resource: snapshot.Cluster.Name,
				Evidence: map[string]any{"unmanaged_indices": unmanaged, "example_indices": examples}, Threshold: "contextual; managed retention is recommended for time-series production data",
				Impact: "Unmanaged growth can exhaust disk and create inconsistent retention behavior.", Recommendation: "Confirm workload requirements and adopt ILM or data-stream lifecycle where appropriate.",
				Confidence: healthmodel.ConfidenceMedium, RootCause: "unmanaged_retention",
			})
		}
		return findings, nil
	})
}

func dataStreamHealth() Checker {
	return newChecker("ES-ILM-002", "Data stream lifecycle", "ILM", "Checks data streams for lifecycle policy coverage.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "data_streams") {
			return nil, skip("deep_data_stream_collection_unavailable")
		}
		var findings []healthmodel.Finding
		for _, stream := range snapshot.DataStreams {
			if stream.ILMPolicy != "" || stream.LifecycleEnabled {
				continue
			}
			findings = append(findings, healthmodel.Finding{
				Severity: healthmodel.SeverityLow, Title: "Data stream has no visible lifecycle policy", ResourceType: "data_stream", Resource: stream.Name,
				Evidence: map[string]any{"generation": stream.Generation, "backing_indices": len(stream.BackingIndices), "ilm_policy": stream.ILMPolicy, "data_stream_lifecycle_enabled": stream.LifecycleEnabled}, Threshold: "ILM or data stream lifecycle for retained time-series data",
				Impact: "Backing indices may grow without automated rollover or retention.", Recommendation: "Confirm whether data stream lifecycle or ILM is configured through its index template; add one if retention is currently unmanaged.",
				Confidence: healthmodel.ConfidenceMedium, RootCause: "unmanaged_retention",
			})
			if len(findings) >= 20 {
				break
			}
		}
		return findings, nil
	})
}

func snapshotHealth(warning, high time.Duration) Checker {
	return newChecker("ES-BACKUP-001", "Snapshot backup health", "Snapshot", "Evaluates configured repositories, latest successful snapshot age, and failures without repository verification.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !snapshot.Snapshots.Available {
			return nil, skip("deep_snapshot_collection_unavailable")
		}
		if snapshot.Snapshots.Repositories == 0 {
			return []healthmodel.Finding{{
				Severity: healthmodel.SeverityHigh, Title: "No snapshot repository is configured", ResourceType: "cluster", Resource: snapshot.Cluster.Name,
				Evidence: map[string]any{"repositories": 0}, Threshold: "at least one operational backup repository",
				Impact: "The cluster has no visible Elasticsearch snapshot backup path.", Recommendation: "Configure and monitor a snapshot repository through an authorized workflow. The health check does not verify or modify repositories.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "backup_unavailable",
			}}, nil
		}
		if snapshot.Snapshots.RepositoriesChecked == 0 {
			return nil, skip("snapshot_history_unavailable")
		}
		var findings []healthmodel.Finding
		if snapshot.Snapshots.Latest == nil || snapshot.Snapshots.Latest.EndTime.IsZero() {
			severity := healthmodel.SeverityHigh
			title := "No successful snapshot was found"
			if snapshot.Snapshots.RepositoriesChecked < snapshot.Snapshots.Repositories || snapshot.Snapshots.RepositoryLimitReached {
				severity = healthmodel.SeverityMedium
				title = "No successful snapshot was found in the checked repositories"
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: title, ResourceType: "cluster", Resource: snapshot.Cluster.Name,
				Evidence: map[string]any{"repositories": snapshot.Snapshots.Repositories, "repositories_checked": snapshot.Snapshots.RepositoriesChecked, "repository_limit_reached": snapshot.Snapshots.RepositoryLimitReached, "failed_or_partial_snapshots": len(snapshot.Snapshots.Failures)}, Threshold: "at least one recent successful snapshot",
				Impact: "Recovery from data loss or cluster failure is not evidenced by a successful snapshot.", Recommendation: "Investigate snapshot scheduling and repository access, then confirm a successful backup through an authorized operation.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "backup_unavailable",
			})
		} else {
			age := snapshot.Timestamp.Sub(snapshot.Snapshots.Latest.EndTime)
			severity := healthmodel.SeverityOK
			if age >= high {
				severity = healthmodel.SeverityHigh
			} else if age >= warning {
				severity = healthmodel.SeverityMedium
			}
			if severity != healthmodel.SeverityOK {
				findings = append(findings, healthmodel.Finding{
					Severity: severity, Title: "Latest successful snapshot is too old", ResourceType: "snapshot", Resource: snapshot.Snapshots.Latest.Repository + "/" + snapshot.Snapshots.Latest.Name,
					Evidence: map[string]any{"latest_successful_snapshot": snapshot.Snapshots.Latest.EndTime, "age_hours": fixed(age.Hours()), "repositories": snapshot.Snapshots.Repositories, "repositories_checked": snapshot.Snapshots.RepositoriesChecked, "repository_limit_reached": snapshot.Snapshots.RepositoryLimitReached, "failed_or_partial_snapshots": len(snapshot.Snapshots.Failures)}, Threshold: fmt.Sprintf("warning %s, high %s", warning, high),
					Impact: "Recovery may lose more data than the intended recovery point objective.", Recommendation: "Restore the scheduled snapshot process and investigate recent partial or failed snapshots.",
					Confidence: healthmodel.ConfidenceHigh, RootCause: "backup_stale",
				})
			}
		}
		if len(snapshot.Snapshots.Failures) > 0 {
			latestFailure := snapshot.Snapshots.Failures[0]
			for _, failed := range snapshot.Snapshots.Failures[1:] {
				if failed.EndTime.After(latestFailure.EndTime) {
					latestFailure = failed
				}
			}
			severity := healthmodel.SeverityInfo
			if snapshot.Snapshots.Latest == nil || latestFailure.EndTime.After(snapshot.Snapshots.Latest.EndTime) {
				severity = healthmodel.SeverityHigh
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Failed or partial snapshots were observed", ResourceType: "snapshot", Resource: latestFailure.Repository + "/" + latestFailure.Name,
				Evidence: map[string]any{"state": latestFailure.State, "end_time": latestFailure.EndTime, "failure_entries": latestFailure.Failures, "failed_or_partial_snapshots": len(snapshot.Snapshots.Failures), "newer_than_latest_success": snapshot.Snapshots.Latest == nil || latestFailure.EndTime.After(snapshot.Snapshots.Latest.EndTime)}, Threshold: "no failed or partial snapshot newer than the latest success",
				Impact: "A failed or partial snapshot may not satisfy the intended recovery point or data coverage.", Recommendation: "Inspect snapshot history and repository logs, correct the failing indices or repository condition, and confirm a later successful snapshot.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "backup_failure",
			})
		}
		return findings, nil
	})
}

func allocationSettings() Checker {
	return newChecker("ES-CONFIG-001", "Shard allocation settings", "Configuration", "Detects disabled or restricted allocation and rebalancing.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		if !collectionSucceeded(snapshot, "cluster_settings") {
			return nil, skip("cluster_settings_unavailable")
		}
		var findings []healthmodel.Finding
		if value, ok := snapshot.ClusterSettings.Effective("cluster.routing.allocation.enable"); ok {
			normalized := strings.ToLower(strings.TrimSpace(value))
			if normalized != "all" && normalized != "" {
				severity := healthmodel.SeverityHigh
				if normalized == "none" {
					severity = healthmodel.SeverityCritical
				}
				findings = append(findings, healthmodel.Finding{
					Severity: severity, Title: "Shard allocation is restricted", ResourceType: "cluster_setting", Resource: "cluster.routing.allocation.enable",
					Evidence: map[string]any{"effective_value": value}, Threshold: "all", Impact: "Recovery, replica placement, and rebalancing can remain blocked after maintenance.",
					Recommendation: "Confirm whether the restriction is an active maintenance control; restore normal allocation only through an authorized change.", Confidence: healthmodel.ConfidenceHigh, RootCause: "allocation_disabled",
				})
			}
		}
		if value, ok := snapshot.ClusterSettings.Effective("cluster.routing.rebalance.enable"); ok {
			normalized := strings.ToLower(strings.TrimSpace(value))
			if normalized == "none" || normalized == "primaries" || normalized == "replicas" {
				findings = append(findings, healthmodel.Finding{
					Severity: healthmodel.SeverityMedium, Title: "Cluster rebalancing is restricted", ResourceType: "cluster_setting", Resource: "cluster.routing.rebalance.enable",
					Evidence: map[string]any{"effective_value": value}, Threshold: "all", Impact: "Shard and disk imbalance may persist after topology changes.",
					Recommendation: "Confirm whether the setting is intentional and time-bounded; change it only through an authorized operation.", Confidence: healthmodel.ConfidenceHigh, RootCause: "allocation_disabled",
				})
			}
		}
		if value, ok := snapshot.ClusterSettings.Effective("cluster.routing.allocation.disk.threshold_enabled"); ok && strings.EqualFold(value, "false") {
			findings = append(findings, healthmodel.Finding{
				Severity: healthmodel.SeverityHigh, Title: "Disk-based shard allocation thresholds are disabled", ResourceType: "cluster_setting", Resource: "cluster.routing.allocation.disk.threshold_enabled",
				Evidence: map[string]any{"effective_value": value}, Threshold: "true", Impact: "Elasticsearch can continue allocating shards to critically full nodes.",
				Recommendation: "Re-enable disk thresholds through an authorized change after understanding why they were disabled.", Confidence: healthmodel.ConfidenceHigh, RootCause: "disk_allocation_protection_disabled",
			})
		}
		return findings, nil
	})
}

func securityHealth(profile config.HealthProfile) Checker {
	return newChecker("ES-SEC-001", "Transport and authentication security", "Security", "Evaluates plaintext HTTP, anonymous API access, and visible HTTP/transport TLS settings.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		var findings []healthmodel.Finding
		if snapshot.Security.AllowPlaintextAuth && snapshot.Security.CredentialsUsed && !snapshot.Security.HTTPSEnabled {
			findings = append(findings, healthmodel.Finding{
				Severity: healthmodel.SeverityCritical, Title: "Credentials were sent over HTTP because plaintext authentication was explicitly allowed", ResourceType: "transport", Resource: "http_plaintext_auth",
				Evidence: map[string]any{"https_enabled": false, "credentials_used": true, "allow_plaintext_auth": true}, Threshold: "HTTPS or no credentials",
				Impact: "The operator override transmitted secrets on an unencrypted Elasticsearch HTTP connection.", Recommendation: "Use HTTPS and keep --allow-plaintext-auth disabled except for explicitly authorized, isolated tests.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "plaintext_auth_override",
			})
		}
		if !snapshot.Security.HTTPSEnabled {
			severity := healthmodel.SeverityHigh
			if snapshot.Security.CredentialsUsed {
				severity = healthmodel.SeverityCritical
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Elasticsearch HTTP traffic is not protected by TLS", ResourceType: "transport", Resource: "http",
				Evidence: map[string]any{"https_enabled": false, "credentials_used": snapshot.Security.CredentialsUsed, "allow_plaintext_auth": snapshot.Security.AllowPlaintextAuth}, Threshold: "HTTPS",
				Impact: "Network observers can read or modify Elasticsearch traffic; credentials sent over HTTP are exposed.", Recommendation: "Enable and verify TLS on the Elasticsearch HTTP interface or its trusted reverse proxy. Avoid sending credentials over HTTP.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "plaintext_http",
			})
		}
		if snapshot.Security.AnonymousAccess {
			severity := healthmodel.SeverityHigh
			if strictAnonymous(profile) {
				severity = healthmodel.SeverityCritical
			}
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "Elasticsearch metadata is accessible without credentials", ResourceType: "security", Resource: "anonymous",
				Evidence: map[string]any{"anonymous_access": true, "profile": profile}, Threshold: "authenticated access for operational APIs",
				Impact: "Unauthenticated users can observe cluster health or more, depending on role permissions.", Recommendation: "Review anonymous access configuration and restrict permissions to the minimum explicitly required.",
				Confidence: healthmodel.ConfidenceHigh, RootCause: "anonymous_access",
			})
		}
		if snapshot.Security.TransportSSLEnabled != nil && !*snapshot.Security.TransportSSLEnabled {
			findings = append(findings, healthmodel.Finding{
				Severity: healthmodel.SeverityCritical, Title: "Node-to-node transport TLS is disabled", ResourceType: "transport", Resource: "node_to_node",
				Evidence: map[string]any{"transport_tls_enabled": false}, Threshold: "true", Impact: "Cluster transport traffic and node authentication are not protected by TLS.",
				Recommendation: "Enable transport TLS on every node through a coordinated, authorized rollout.", Confidence: healthmodel.ConfidenceHigh, RootCause: "transport_tls_disabled",
			})
		}
		if snapshot.Security.HTTPSSLEnabled != nil && snapshot.Security.HTTPSEnabled != *snapshot.Security.HTTPSSLEnabled {
			findings = append(findings, healthmodel.Finding{
				Severity: healthmodel.SeverityMedium, Title: "Observed HTTPS and node HTTP TLS settings differ", ResourceType: "transport", Resource: "http_tls_configuration",
				Evidence: map[string]any{"observed_https": snapshot.Security.HTTPSEnabled, "node_http_tls_enabled": *snapshot.Security.HTTPSSLEnabled}, Threshold: "consistent expected TLS termination",
				Impact: "TLS may terminate at an intermediary or node settings may be inconsistent, complicating the trust boundary.", Recommendation: "Document and verify the intended TLS termination point and trusted proxy path.",
				Confidence: healthmodel.ConfidenceMedium, RootCause: "tls_topology_mismatch",
			})
		}
		return findings, nil
	})
}

func certificateHealth(threshold config.DaysThreshold) Checker {
	return newChecker("ES-SEC-002", "TLS certificate", "Security", "Checks certificate validity, hostname matching, and remaining lifetime.", func(_ context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
		certificate := snapshot.Security.Certificate
		if !snapshot.Security.HTTPSEnabled || certificate == nil {
			return nil, skip("tls_certificate_unavailable")
		}
		var findings []healthmodel.Finding
		if !certificate.HostnameValid {
			findings = append(findings, healthmodel.Finding{
				Severity: healthmodel.SeverityCritical, Title: "TLS certificate does not match the target hostname", ResourceType: "certificate", Resource: certificate.Subject,
				Evidence: map[string]any{"hostname_valid": false, "issuer": certificate.Issuer, "valid_until": certificate.ValidUntil}, Threshold: "valid hostname",
				Impact: "Clients cannot securely authenticate the endpoint identity.", Recommendation: "Install a certificate whose SAN covers the target hostname and keep certificate verification enabled.", Confidence: healthmodel.ConfidenceHigh, RootCause: "tls_certificate_invalid",
			})
		}
		severity := healthmodel.SeverityOK
		switch {
		case certificate.RemainingDays < 0:
			severity = healthmodel.SeverityCritical
		case certificate.RemainingDays < threshold.Critical:
			severity = healthmodel.SeverityCritical
		case certificate.RemainingDays < threshold.High:
			severity = healthmodel.SeverityHigh
		case certificate.RemainingDays < threshold.Warning:
			severity = healthmodel.SeverityMedium
		}
		if severity != healthmodel.SeverityOK {
			findings = append(findings, healthmodel.Finding{
				Severity: severity, Title: "TLS certificate is expired or approaching expiration", ResourceType: "certificate", Resource: certificate.Subject,
				Evidence: map[string]any{"issuer": certificate.Issuer, "valid_from": certificate.ValidFrom, "valid_until": certificate.ValidUntil, "remaining_days": certificate.RemainingDays, "self_signed": certificate.SelfSigned}, Threshold: fmt.Sprintf("warning < %d days, high < %d days, critical < %d days", threshold.Warning, threshold.High, threshold.Critical),
				Impact: "Certificate expiry causes verified clients and health checks to lose connectivity.", Recommendation: "Renew and deploy the certificate before expiration, preserving hostname and trust-chain validation.", Confidence: healthmodel.ConfidenceHigh, RootCause: "tls_certificate_expiry",
			})
		} else if certificate.SelfSigned {
			findings = append(findings, healthmodel.Finding{
				Severity: healthmodel.SeverityInfo, Title: "TLS certificate is self-signed", ResourceType: "certificate", Resource: certificate.Subject,
				Evidence: map[string]any{"self_signed": true, "valid_until": certificate.ValidUntil}, Threshold: "informational; private trust may be intentional",
				Impact: "Clients require explicit trust distribution; this is not inherently insecure when the trust root is managed.", Recommendation: "Ensure the private CA/certificate is distributed and rotated through a controlled trust process; do not rely on --insecure.", Confidence: healthmodel.ConfidenceHigh, RootCause: "private_tls_trust",
			})
		}
		return findings, nil
	})
}
