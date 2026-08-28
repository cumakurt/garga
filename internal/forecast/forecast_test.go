package forecast

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

const gibibyte = int64(1 << 30)

func TestAnalyzeProjectsDiskThresholdsFromLinearStoreGrowth(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	snapshots := []*healthmodel.Baseline{
		forecastBaseline(start.Add(72*time.Hour), "cluster-a", 40*gibibyte, 100*gibibyte, 40*gibibyte),
		forecastBaseline(start, "cluster-a", 10*gibibyte, 100*gibibyte, 70*gibibyte),
		forecastBaseline(start.Add(48*time.Hour), "cluster-a", 30*gibibyte, 100*gibibyte, 50*gibibyte),
		forecastBaseline(start.Add(24*time.Hour), "cluster-a", 20*gibibyte, 100*gibibyte, 60*gibibyte),
	}
	report, err := Analyze(snapshots)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if report.Samples != 4 || report.WindowHours != 72 || report.Growth.Confidence != "high" || report.Growth.Direction != "growing" {
		t.Fatalf("forecast metadata = %#v", report)
	}
	if math.Abs(report.Growth.BytesPerDay-float64(10*gibibyte)) > 1 {
		t.Fatalf("bytes per day = %f, want %d", report.Growth.BytesPerDay, 10*gibibyte)
	}
	if report.Growth.R2 < 0.999999 {
		t.Fatalf("R2 = %f", report.Growth.R2)
	}
	if report.Capacity.UsagePercent != 60 {
		t.Fatalf("usage percent = %f, want 60", report.Capacity.UsagePercent)
	}
	first := report.Projections[0]
	if first.State != "projected" || first.Days == nil || math.Abs(*first.Days-2.5) > 0.0001 {
		t.Fatalf("85%% projection = %#v", first)
	}
	wantDate := report.WindowEnd.Add(60 * time.Hour)
	if first.EstimatedAt == nil || !first.EstimatedAt.Equal(wantDate) {
		t.Fatalf("85%% estimated_at = %v, want %v", first.EstimatedAt, wantDate)
	}
}

func TestAnalyzeDoesNotProjectStableUsage(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	report, err := Analyze([]*healthmodel.Baseline{
		forecastBaseline(start, "cluster-a", 10*gibibyte, 100*gibibyte, 50*gibibyte),
		forecastBaseline(start.Add(24*time.Hour), "cluster-a", 10*gibibyte, 100*gibibyte, 50*gibibyte),
		forecastBaseline(start.Add(48*time.Hour), "cluster-a", 10*gibibyte, 100*gibibyte, 50*gibibyte),
		forecastBaseline(start.Add(72*time.Hour), "cluster-a", 10*gibibyte, 100*gibibyte, 50*gibibyte),
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if report.Growth.Direction != "stable" {
		t.Fatalf("direction = %q", report.Growth.Direction)
	}
	for _, projection := range report.Projections {
		if projection.State != "not_projected" || projection.EstimatedAt != nil {
			t.Errorf("stable projection = %#v", projection)
		}
	}
}

func TestAnalyzeRejectsIncompatibleSnapshots(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		snapshots []*healthmodel.Baseline
		want      string
	}{
		{
			name: "different cluster",
			snapshots: []*healthmodel.Baseline{
				forecastBaseline(start, "cluster-a", 1, 100, 50),
				forecastBaseline(start.Add(time.Hour), "cluster-b", 2, 100, 49),
			},
			want: "different clusters",
		},
		{
			name: "duplicate timestamp",
			snapshots: []*healthmodel.Baseline{
				forecastBaseline(start, "cluster-a", 1, 100, 50),
				forecastBaseline(start, "cluster-a", 2, 100, 49),
			},
			want: "timestamps must be unique",
		},
		{
			name: "capacity drift",
			snapshots: []*healthmodel.Baseline{
				forecastBaseline(start, "cluster-a", 1, 100, 50),
				forecastBaseline(start.Add(time.Hour), "cluster-a", 2, 120, 60),
			},
			want: "capacity drift",
		},
		{
			name: "aggregate overflow",
			snapshots: []*healthmodel.Baseline{
				{
					SchemaVersion: healthmodel.BaselineSchemaVersion, Timestamp: start, ClusterUUID: "cluster-a", ClusterStoreBytes: 1,
					Nodes: map[string]healthmodel.NodeCounters{"a": {DiskTotalBytes: math.MaxInt64, DiskAvailableBytes: 1}, "b": {DiskTotalBytes: 1, DiskAvailableBytes: 1}},
				},
				forecastBaseline(start.Add(time.Hour), "cluster-a", 2, 100, 50),
			},
			want: "overflow",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Analyze(test.snapshots)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Analyze() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestForecastRenderersAreDeterministic(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	report, err := Analyze([]*healthmodel.Baseline{
		forecastBaseline(start, "cluster-a", 10*gibibyte, 100*gibibyte, 70*gibibyte),
		forecastBaseline(start.Add(24*time.Hour), "cluster-a", 20*gibibyte, 100*gibibyte, 60*gibibyte),
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	for _, format := range []Format{FormatConsole, FormatJSON} {
		var first bytes.Buffer
		var second bytes.Buffer
		if err := Write(&first, format, report); err != nil {
			t.Fatalf("Write(%s) error = %v", format, err)
		}
		if err := Write(&second, format, report); err != nil {
			t.Fatalf("Write(%s) second error = %v", format, err)
		}
		if !bytes.Equal(first.Bytes(), second.Bytes()) || !strings.Contains(first.String(), "cluster-a") && format == FormatJSON {
			t.Fatalf("Write(%s) output is invalid: %s", format, first.String())
		}
	}
}

func forecastBaseline(timestamp time.Time, cluster string, store, total, available int64) *healthmodel.Baseline {
	return &healthmodel.Baseline{
		SchemaVersion:     healthmodel.BaselineSchemaVersion,
		Timestamp:         timestamp,
		ClusterUUID:       cluster,
		ClusterStoreBytes: store,
		Nodes: map[string]healthmodel.NodeCounters{
			"node-a": {DiskTotalBytes: total, DiskAvailableBytes: available},
		},
	}
}
