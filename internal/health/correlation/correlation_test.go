package correlation

import (
	"testing"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func TestAnalyzeCorrelatesKnownRootCauses(t *testing.T) {
	t.Parallel()
	findings := []healthmodel.Finding{
		{ID: "ES-DISK-001", RootCause: "disk_pressure:node-1", Severity: healthmodel.SeverityHigh, Resource: "data-1"},
		{ID: "ES-SHARD-001", RootCause: "disk_allocation_pressure", Severity: healthmodel.SeverityCritical, Resource: "cluster"},
		{ID: "ES-JVM-001", RootCause: "jvm_pressure:node-1", Severity: healthmodel.SeverityHigh, Resource: "data-1"},
		{ID: "ES-MEM-002", RootCause: "memory_pressure:node-1", Severity: healthmodel.SeverityMedium, Resource: "data-1"},
		{ID: "ES-SHARD-005", RootCause: "shard_imbalance", Severity: healthmodel.SeverityMedium, Resource: "cluster"},
		{ID: "ES-DISK-002", RootCause: "disk_imbalance", Severity: healthmodel.SeverityMedium, Resource: "cluster"},
	}
	correlations := Analyze(findings)
	if len(correlations) != 3 {
		t.Fatalf("Analyze() = %#v, want 3 correlations", correlations)
	}
	titles := map[string]healthmodel.Severity{}
	for _, item := range correlations {
		titles[item.Title] = item.Severity
	}
	if titles["Disk pressure is preventing normal allocation or writes"] != healthmodel.SeverityCritical {
		t.Fatalf("disk correlation = %#v", correlations)
	}
	if titles["JVM memory pressure has multiple supporting signals"] != healthmodel.SeverityHigh {
		t.Fatalf("jvm correlation = %#v", correlations)
	}
	if titles["Shard placement is correlated with disk imbalance"] != healthmodel.SeverityMedium {
		t.Fatalf("imbalance correlation = %#v", correlations)
	}
}

func TestAnalyzeIgnoresUnrelatedFindings(t *testing.T) {
	t.Parallel()
	if got := Analyze([]healthmodel.Finding{{ID: "ES-CLUSTER-001", RootCause: "cluster_availability", Severity: healthmodel.SeverityMedium}}); len(got) != 0 {
		t.Fatalf("Analyze() = %#v, want none", got)
	}
}
