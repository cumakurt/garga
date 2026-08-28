package checker

import (
	"context"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/config"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func TestDefaultRegistryCount(t *testing.T) {
	t.Parallel()
	registry, err := DefaultRegistry(config.Defaults().Health)
	if err != nil {
		t.Fatal(err)
	}
	if registry.Count() != 38 {
		t.Fatalf("registry count = %d, want 38", registry.Count())
	}
}

func TestProfilesChangeAvailabilityAndSecuritySeverity(t *testing.T) {
	t.Parallel()
	single := healthySnapshot()
	single.Cluster.Nodes = 1
	single.Nodes = single.Nodes[:1]
	single.Security.AnonymousAccess = true

	twoMaster := healthySnapshot()
	twoMaster.Nodes = twoMaster.Nodes[:2]
	twoMaster.Cluster.Nodes = 2

	tests := []struct {
		name     string
		profile  config.HealthProfile
		snapshot *healthmodel.ClusterSnapshot
		id       string
		severity healthmodel.Severity
	}{
		{name: "small single-node info", profile: config.HealthProfileSmall, snapshot: single, id: "ES-AVAIL-001", severity: healthmodel.SeverityInfo},
		{name: "standard single-node medium", profile: config.HealthProfileStandard, snapshot: single, id: "ES-AVAIL-001", severity: healthmodel.SeverityMedium},
		{name: "large two-master high", profile: config.HealthProfileLarge, snapshot: twoMaster, id: "ES-NODE-002", severity: healthmodel.SeverityHigh},
		{name: "standard two-master medium", profile: config.HealthProfileStandard, snapshot: twoMaster, id: "ES-NODE-002", severity: healthmodel.SeverityMedium},
		{name: "production anonymous critical", profile: config.HealthProfileProduction, snapshot: single, id: "ES-SEC-001", severity: healthmodel.SeverityCritical},
		{name: "standard anonymous high", profile: config.HealthProfileStandard, snapshot: single, id: "ES-SEC-001", severity: healthmodel.SeverityHigh},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults().Health
			cfg.Profile = test.profile
			registry, err := DefaultRegistry(cfg)
			if err != nil {
				t.Fatal(err)
			}
			findings, _ := registry.Evaluate(context.Background(), test.snapshot)
			var got healthmodel.Severity
			found := false
			for _, finding := range findings {
				if finding.ID != test.id {
					continue
				}
				if healthmodel.SeverityRank(finding.Severity) > healthmodel.SeverityRank(got) {
					got = finding.Severity
				}
				found = true
			}
			if !found || got != test.severity {
				t.Fatalf("finding %s severity = %s found=%t; findings=%#v", test.id, got, found, findings)
			}
		})
	}
}

func TestDefaultRegistryScenarios(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*healthmodel.ClusterSnapshot)
		wantIDs []string
	}{
		{name: "healthy"},
		{name: "critical resource pressure", mutate: func(snapshot *healthmodel.ClusterSnapshot) {
			snapshot.ClusterHealth.Status = "red"
			snapshot.ClusterHealth.UnassignedShards = 1
			snapshot.Nodes[0].JVM.HeapUsedPercent = 96
			snapshot.Nodes[0].JVM.HeapUsedBytes = 96
			snapshot.Nodes[0].Filesystem.AvailableBytes = 3
			snapshot.Indices[0].Health = "red"
			snapshot.Indices[0].Replicas = 0
			snapshot.Indices[0].Documents = 10_000
			snapshot.Indices[0].DeletedDocuments = 10_000
			snapshot.Indices[0].Settings = map[string]string{"index.blocks.read_only_allow_delete": "true"}
			snapshot.Shards = []healthmodel.Shard{{Index: "logs", Number: 0, Primary: true, State: "UNASSIGNED", UnassignedReason: "ALLOCATION_FAILED"}}
		}, wantIDs: []string{"ES-CLUSTER-001", "ES-JVM-001", "ES-DISK-001", "ES-SHARD-001", "ES-INDEX-001", "ES-INDEX-002", "ES-INDEX-003", "ES-INDEX-006"}},
		{name: "missing metrics", mutate: func(snapshot *healthmodel.ClusterSnapshot) {
			snapshot.Collection.Collectors = nil
			snapshot.Nodes = nil
			snapshot.Indices = nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			snapshot := healthySnapshot()
			if test.mutate != nil {
				test.mutate(snapshot)
			}
			registry, err := DefaultRegistry(config.Defaults().Health)
			if err != nil {
				t.Fatalf("DefaultRegistry() error = %v", err)
			}
			findings, results := registry.Evaluate(context.Background(), snapshot)
			if len(results) != registry.Count() {
				t.Fatalf("check results = %d, want %d", len(results), registry.Count())
			}
			ids := make(map[string]bool)
			for _, finding := range findings {
				ids[finding.ID] = true
			}
			for _, want := range test.wantIDs {
				if !ids[want] {
					t.Errorf("missing finding %s; findings = %#v", want, findings)
				}
			}
			if len(test.wantIDs) == 0 && len(findings) != 0 {
				t.Fatalf("findings = %#v, want none", findings)
			}
		})
	}
}

func TestThreadPoolCheckerUsesBaselineDelta(t *testing.T) {
	t.Parallel()
	snapshot := healthySnapshot()
	snapshot.Nodes[0].ThreadPools = map[string]healthmodel.ThreadPool{"search": {Rejected: 10}}
	snapshot.Baseline = &healthmodel.Baseline{
		SchemaVersion: healthmodel.BaselineSchemaVersion, Timestamp: snapshot.Timestamp.Add(-time.Minute), ClusterUUID: snapshot.Cluster.UUID,
		Nodes: map[string]healthmodel.NodeCounters{"node-1": {ThreadPoolRejected: map[string]int64{"search": 5}}},
	}
	registry, err := NewRegistry(threadPools(100))
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := registry.Evaluate(context.Background(), snapshot)
	if len(findings) != 1 || findings[0].Severity != healthmodel.SeverityMedium || findings[0].Evidence["rejected_delta"] != int64(5) {
		t.Fatalf("findings = %#v", findings)
	}
}

func TestRegistrySkipsUnsupportedVersion(t *testing.T) {
	t.Parallel()
	snapshot := healthySnapshot()
	snapshot.Cluster.Version.Number = "6.8.23"
	registry, err := DefaultRegistry(config.Defaults().Health)
	if err != nil {
		t.Fatal(err)
	}
	findings, results := registry.Evaluate(context.Background(), snapshot)
	if len(findings) != 0 {
		t.Fatalf("findings = %#v", findings)
	}
	for _, result := range results {
		if result.Status != "skipped" || result.Reason != "unsupported_version" {
			t.Fatalf("result = %#v", result)
		}
	}
}

func BenchmarkRegistryEvaluate(b *testing.B) {
	registry, err := DefaultRegistry(config.Defaults().Health)
	if err != nil {
		b.Fatal(err)
	}
	snapshot := healthySnapshot()
	b.ReportAllocs()
	for b.Loop() {
		registry.Evaluate(context.Background(), snapshot)
	}
}

func healthySnapshot() *healthmodel.ClusterSnapshot {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	collectors := []healthmodel.CollectorResult{
		{Name: "cluster_health", Status: "success"}, {Name: "cluster_settings", Status: "success"}, {Name: "nodes_info", Status: "success"}, {Name: "nodes_stats", Status: "success"},
		{Name: "indices", Status: "success"}, {Name: "index_settings", Status: "success"}, {Name: "shards", Status: "success"}, {Name: "pending_tasks", Status: "success"},
	}
	return &healthmodel.ClusterSnapshot{
		SchemaVersion: healthmodel.SnapshotSchemaVersion, Timestamp: now,
		Cluster:         healthmodel.ClusterInfo{Name: "fixture", UUID: "cluster-uuid", Version: healthmodel.Version{Number: "8.19.19"}, Nodes: 3, DataNodes: 3, Indices: 1, Shards: 3},
		ClusterHealth:   healthmodel.ClusterHealth{Status: "green", NumberOfNodes: 3, NumberOfDataNodes: 3, ActiveShardsPercentAsNumber: 100},
		ClusterSettings: healthmodel.ClusterSettings{Defaults: map[string]string{"cluster.routing.allocation.disk.watermark.low": "85%", "cluster.routing.allocation.disk.watermark.high": "90%", "cluster.routing.allocation.disk.watermark.flood_stage": "95%"}},
		Nodes: []healthmodel.Node{
			{ID: "node-1", Name: "data-1", Roles: []string{"data_hot", "master"}, AvailableProcessors: 4, JVM: healthmodel.JVMStats{HeapMaxBytes: 100, HeapUsedBytes: 20, HeapUsedPercent: 20}, Filesystem: healthmodel.FilesystemStats{TotalBytes: 100, AvailableBytes: 80}},
			{ID: "node-2", Name: "data-2", Roles: []string{"data_hot", "master"}, AvailableProcessors: 4, JVM: healthmodel.JVMStats{HeapMaxBytes: 100, HeapUsedBytes: 20, HeapUsedPercent: 20}, Filesystem: healthmodel.FilesystemStats{TotalBytes: 100, AvailableBytes: 80}},
			{ID: "node-3", Name: "data-3", Roles: []string{"data_hot", "master"}, AvailableProcessors: 4, JVM: healthmodel.JVMStats{HeapMaxBytes: 100, HeapUsedBytes: 20, HeapUsedPercent: 20}, Filesystem: healthmodel.FilesystemStats{TotalBytes: 100, AvailableBytes: 80}},
		},
		Indices:  []healthmodel.Index{{Name: "logs", Health: "green", Status: "open", PrimaryShards: 1, Replicas: 2, Documents: 100, StoreBytes: 1 << 30, CreationTime: now.Add(-24 * time.Hour)}},
		Shards:   []healthmodel.Shard{{Index: "logs", Number: 0, Primary: true, State: "STARTED", StoreBytes: 1 << 30, Node: "data-1"}, {Index: "logs", Number: 0, State: "STARTED", StoreBytes: 1 << 30, Node: "data-2"}, {Index: "logs", Number: 0, State: "STARTED", StoreBytes: 1 << 30, Node: "data-3"}},
		Security: healthmodel.SecurityState{HTTPSEnabled: true}, Collection: healthmodel.CollectionState{Collectors: collectors},
	}
}
