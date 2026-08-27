package checker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cumakurt/garga/internal/config"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

// Checker evaluates normalized state and never performs Elasticsearch I/O.
type Checker interface {
	ID() string
	Name() string
	Category() string
	Description() string
	SupportedVersions() healthmodel.VersionConstraint
	Check(context.Context, *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error)
}

type Registry struct {
	checks []Checker
}

func DefaultRegistry(cfg config.HealthConfig) (*Registry, error) {
	checks := []Checker{
		clusterStatus(), pendingTasks(cfg), singleNode(cfg.Profile), roleDistribution(cfg.Profile),
		jvmHeap(cfg.Thresholds.JVM), garbageCollection(), cpuHealth(cfg.Thresholds.CPU),
		swapUsage(), physicalMemory(cfg.Thresholds.Memory), fileDescriptors(cfg.Thresholds.FileDescriptors),
		diskHealth(cfg.Thresholds.Disk), diskImbalance(variationForProfile(cfg.Thresholds.DiskImbalance, cfg.Profile)), diskCapacityForecast(cfg.Thresholds.Disk),
		threadPools(cfg.Thresholds.ThreadPoolQueueHigh), circuitBreakers(), indexingPressure(),
		unassignedShards(), shardCount(cfg.Profile), smallShards(cfg.Thresholds.ShardSize.Small),
		largeShards(cfg.Thresholds.ShardSize.LargeWarning, cfg.Thresholds.ShardSize.LargeHigh),
		shardImbalance(variationForProfile(cfg.Thresholds.ShardImbalance, cfg.Profile)), indexHealth(), zeroReplicas(cfg.Profile),
		deletedDocuments(cfg.Thresholds.DeletedDocuments), emptyIndices(), oldIndices(), indexBlocks(),
		performance(), mergeAndRefreshPressure(cfg.Profile), segments(cfg.Profile), ilmHealth(), dataStreamHealth(), longTasks(cfg.Thresholds.LongTaskWarning),
		snapshotHealth(cfg.Thresholds.BackupWarning, cfg.Thresholds.BackupHigh), allocationSettings(),
		securityHealth(cfg.Profile), certificateHealth(cfg.Thresholds.Certificate),
	}
	return NewRegistry(checks...)
}

func NewRegistry(checks ...Checker) (*Registry, error) {
	seen := make(map[string]struct{}, len(checks))
	cloned := make([]Checker, 0, len(checks))
	for _, check := range checks {
		if check == nil || strings.TrimSpace(check.ID()) == "" {
			return nil, fmt.Errorf("create health check registry: checker and ID are required")
		}
		if _, exists := seen[check.ID()]; exists {
			return nil, fmt.Errorf("create health check registry: duplicate checker ID %q", check.ID())
		}
		if err := check.SupportedVersions().Validate(); err != nil {
			return nil, fmt.Errorf("create health check registry: checker %q has invalid version constraint: %w", check.ID(), err)
		}
		seen[check.ID()] = struct{}{}
		cloned = append(cloned, check)
	}
	return &Registry{checks: cloned}, nil
}

func (registry *Registry) Evaluate(ctx context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, []healthmodel.CheckResult) {
	if registry == nil || snapshot == nil {
		return nil, nil
	}
	var findings []healthmodel.Finding
	results := make([]healthmodel.CheckResult, 0, len(registry.checks))
	for _, check := range registry.checks {
		if err := ctx.Err(); err != nil {
			results = append(results, healthmodel.CheckResult{ID: check.ID(), Status: "failed", Reason: "canceled"})
			break
		}
		if !check.SupportedVersions().Supports(snapshot.Cluster.Version.Number) {
			results = append(results, healthmodel.CheckResult{ID: check.ID(), Status: "skipped", Reason: "unsupported_version"})
			continue
		}
		checkFindings, err := check.Check(ctx, snapshot)
		if err != nil {
			var skipped *SkippedError
			if errors.As(err, &skipped) {
				results = append(results, healthmodel.CheckResult{ID: check.ID(), Status: "skipped", Reason: skipped.Reason})
			} else {
				results = append(results, healthmodel.CheckResult{ID: check.ID(), Status: "failed", Reason: "checker_error"})
			}
			continue
		}
		for index := range checkFindings {
			if checkFindings[index].ID == "" {
				checkFindings[index].ID = check.ID()
			}
			if checkFindings[index].Category == "" {
				checkFindings[index].Category = check.Category()
			}
		}
		findings = append(findings, checkFindings...)
		status := "passed"
		if len(checkFindings) > 0 {
			status = "finding"
		}
		results = append(results, healthmodel.CheckResult{ID: check.ID(), Status: status, Findings: len(checkFindings)})
	}
	findings = deduplicate(findings)
	sort.SliceStable(findings, func(left, right int) bool {
		leftRank, rightRank := healthmodel.SeverityRank(findings[left].Severity), healthmodel.SeverityRank(findings[right].Severity)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if findings[left].ID != findings[right].ID {
			return findings[left].ID < findings[right].ID
		}
		return findings[left].Resource < findings[right].Resource
	})
	return findings, results
}

func (registry *Registry) Count() int {
	if registry == nil {
		return 0
	}
	return len(registry.checks)
}

type SkippedError struct{ Reason string }

func (err *SkippedError) Error() string { return "health check skipped: " + err.Reason }

func skip(reason string) error { return &SkippedError{Reason: reason} }

func deduplicate(findings []healthmodel.Finding) []healthmodel.Finding {
	seen := make(map[string]struct{}, len(findings))
	result := make([]healthmodel.Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.StableKey()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, finding)
	}
	return result
}

type baseChecker struct {
	id, name, category, description string
}

func (checker baseChecker) ID() string          { return checker.id }
func (checker baseChecker) Name() string        { return checker.name }
func (checker baseChecker) Category() string    { return checker.category }
func (checker baseChecker) Description() string { return checker.description }
func (checker baseChecker) SupportedVersions() healthmodel.VersionConstraint {
	return healthmodel.VersionConstraint{Min: "7.17.0", Max: "9.999.999"}
}

type checkFunction func(context.Context, *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error)

type functionalChecker struct {
	baseChecker
	check checkFunction
}

func (checker functionalChecker) Check(ctx context.Context, snapshot *healthmodel.ClusterSnapshot) ([]healthmodel.Finding, error) {
	return checker.check(ctx, snapshot)
}

func newChecker(id, name, category, description string, check checkFunction) Checker {
	return functionalChecker{baseChecker: baseChecker{id: id, name: name, category: category, description: description}, check: check}
}
