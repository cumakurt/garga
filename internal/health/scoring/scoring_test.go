package scoring

import (
	"testing"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func TestCalculateDeduplicatesRootCausePenalty(t *testing.T) {
	t.Parallel()
	findings := []healthmodel.Finding{
		{ID: "ES-DISK-001", Severity: healthmodel.SeverityHigh, RootCause: "disk"},
		{ID: "ES-SHARD-001", Severity: healthmodel.SeverityCritical, RootCause: "disk"},
		{ID: "ES-INDEX-001", Severity: healthmodel.SeverityMedium, RootCause: "availability"},
		{ID: "ES-INFO-001", Severity: healthmodel.SeverityInfo, RootCause: "history"},
	}
	result := Calculate(findings)
	if result.Score != 70 || result.Health != "Degraded" {
		t.Fatalf("Calculate() = %#v, want score 70 Degraded", result)
	}
	if result.Counts[healthmodel.SeverityHigh] != 1 || result.Counts[healthmodel.SeverityCritical] != 1 {
		t.Fatalf("severity counts = %#v", result.Counts)
	}
}
