package forecast

import (
	"fmt"
	"math"
	"sort"
	"time"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

const (
	SchemaVersion                  = "0.1"
	MaxSnapshots                   = 64
	MaxTotalSnapshotBytes          = 64 << 20
	MinWindow                      = 10 * time.Minute
	MaxCapacityDrift               = 0.05
	MinMeaningfulGrowthBytesPerDay = 1 << 20
	maxProjectionDays              = 3650.0
)

type Capacity struct {
	StoreBytes     int64   `json:"store_bytes"`
	DiskTotalBytes int64   `json:"disk_total_bytes"`
	DiskUsedBytes  int64   `json:"disk_used_bytes"`
	DiskFreeBytes  int64   `json:"disk_free_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
}

type Growth struct {
	BytesPerSecond float64 `json:"bytes_per_second"`
	BytesPerDay    float64 `json:"bytes_per_day"`
	R2             float64 `json:"r_squared"`
	Direction      string  `json:"direction"`
	Confidence     string  `json:"confidence"`
}

type Projection struct {
	ThresholdPercent int        `json:"threshold_percent"`
	TargetUsedBytes  int64      `json:"target_used_bytes"`
	RemainingBytes   int64      `json:"remaining_bytes"`
	State            string     `json:"state"`
	Days             *float64   `json:"days,omitempty"`
	EstimatedAt      *time.Time `json:"estimated_at,omitempty"`
}

type Report struct {
	SchemaVersion string       `json:"schema_version"`
	ClusterUUID   string       `json:"cluster_uuid"`
	Samples       int          `json:"samples"`
	WindowStart   time.Time    `json:"window_start"`
	WindowEnd     time.Time    `json:"window_end"`
	WindowHours   float64      `json:"window_hours"`
	Capacity      Capacity     `json:"capacity"`
	Growth        Growth       `json:"growth"`
	Projections   []Projection `json:"projections"`
}

func Analyze(input []*healthmodel.Baseline) (Report, error) {
	if len(input) < 2 {
		return Report{}, fmt.Errorf("forecast requires at least 2 snapshots")
	}
	if len(input) > MaxSnapshots {
		return Report{}, fmt.Errorf("forecast exceeds %d snapshots", MaxSnapshots)
	}
	snapshots := make([]*healthmodel.Baseline, len(input))
	copy(snapshots, input)
	for _, snapshot := range snapshots {
		if snapshot == nil || snapshot.SchemaVersion != healthmodel.BaselineSchemaVersion || snapshot.Timestamp.IsZero() || snapshot.ClusterUUID == "" {
			return Report{}, fmt.Errorf("forecast snapshot metadata is missing or unsupported")
		}
	}
	sort.Slice(snapshots, func(left, right int) bool { return snapshots[left].Timestamp.Before(snapshots[right].Timestamp) })
	clusterUUID := snapshots[0].ClusterUUID
	diskTotals := make([]int64, len(snapshots))
	diskAvailable := make([]int64, len(snapshots))
	for index, snapshot := range snapshots {
		if snapshot.ClusterUUID != clusterUUID {
			return Report{}, fmt.Errorf("forecast snapshots belong to different clusters")
		}
		if index > 0 && !snapshot.Timestamp.After(snapshots[index-1].Timestamp) {
			return Report{}, fmt.Errorf("forecast snapshot timestamps must be unique")
		}
		if snapshot.ClusterStoreBytes < 0 {
			return Report{}, fmt.Errorf("forecast snapshot store size is invalid")
		}
		for _, node := range snapshot.Nodes {
			if node.DiskTotalBytes <= 0 || node.DiskAvailableBytes < 0 || node.DiskAvailableBytes > node.DiskTotalBytes {
				return Report{}, fmt.Errorf("forecast snapshot disk counters are invalid")
			}
			if node.DiskTotalBytes > math.MaxInt64-diskTotals[index] || node.DiskAvailableBytes > math.MaxInt64-diskAvailable[index] {
				return Report{}, fmt.Errorf("forecast snapshot aggregate disk counters overflow")
			}
			diskTotals[index] += node.DiskTotalBytes
			diskAvailable[index] += node.DiskAvailableBytes
		}
		if diskTotals[index] <= 0 {
			return Report{}, fmt.Errorf("forecast snapshot has no disk capacity data")
		}
	}
	window := snapshots[len(snapshots)-1].Timestamp.Sub(snapshots[0].Timestamp)
	if window < MinWindow {
		return Report{}, fmt.Errorf("forecast window must span at least %s", MinWindow)
	}
	minimumTotal, maximumTotal := diskTotals[0], diskTotals[0]
	for _, total := range diskTotals[1:] {
		minimumTotal = min(minimumTotal, total)
		maximumTotal = max(maximumTotal, total)
	}
	if float64(maximumTotal-minimumTotal)/float64(maximumTotal) > MaxCapacityDrift {
		return Report{}, fmt.Errorf("forecast disk capacity drift exceeds %.0f%%", MaxCapacityDrift*100)
	}

	slope, rSquared := regression(snapshots)
	bytesPerDay := slope * 24 * 60 * 60
	direction := "stable"
	if bytesPerDay >= MinMeaningfulGrowthBytesPerDay {
		direction = "growing"
	} else if bytesPerDay <= -MinMeaningfulGrowthBytesPerDay {
		direction = "shrinking"
	}
	latestIndex := len(snapshots) - 1
	used := diskTotals[latestIndex] - diskAvailable[latestIndex]
	report := Report{
		SchemaVersion: SchemaVersion,
		ClusterUUID:   clusterUUID,
		Samples:       len(snapshots),
		WindowStart:   snapshots[0].Timestamp,
		WindowEnd:     snapshots[latestIndex].Timestamp,
		WindowHours:   window.Hours(),
		Capacity: Capacity{
			StoreBytes: snapshots[latestIndex].ClusterStoreBytes, DiskTotalBytes: diskTotals[latestIndex],
			DiskUsedBytes: used, DiskFreeBytes: diskAvailable[latestIndex], UsagePercent: percentage(used, diskTotals[latestIndex]),
		},
		Growth: Growth{
			BytesPerSecond: slope, BytesPerDay: bytesPerDay, R2: rSquared, Direction: direction,
			Confidence: confidence(len(snapshots), window, rSquared),
		},
	}
	report.Projections = projections(report.WindowEnd, report.Capacity, report.Growth)
	return report, nil
}

func regression(snapshots []*healthmodel.Baseline) (float64, float64) {
	start := snapshots[0].Timestamp
	var meanX, meanY float64
	for _, snapshot := range snapshots {
		meanX += snapshot.Timestamp.Sub(start).Seconds()
		meanY += float64(snapshot.ClusterStoreBytes)
	}
	meanX /= float64(len(snapshots))
	meanY /= float64(len(snapshots))
	var covariance, varianceX, varianceY float64
	for _, snapshot := range snapshots {
		x := snapshot.Timestamp.Sub(start).Seconds() - meanX
		y := float64(snapshot.ClusterStoreBytes) - meanY
		covariance += x * y
		varianceX += x * x
		varianceY += y * y
	}
	if varianceX == 0 {
		return 0, 0
	}
	slope := covariance / varianceX
	if varianceY == 0 {
		return slope, 1
	}
	rSquared := covariance * covariance / (varianceX * varianceY)
	return slope, math.Max(0, math.Min(1, rSquared))
}

func confidence(samples int, window time.Duration, rSquared float64) string {
	switch {
	case samples >= 4 && window >= 24*time.Hour && rSquared >= 0.9:
		return "high"
	case samples >= 3 && window >= 6*time.Hour && rSquared >= 0.6:
		return "medium"
	default:
		return "low"
	}
}

func projections(at time.Time, capacity Capacity, growth Growth) []Projection {
	result := make([]Projection, 0, 3)
	for _, threshold := range []int{85, 90, 95} {
		target := int64(math.Ceil(float64(capacity.DiskTotalBytes) * float64(threshold) / 100))
		remaining := target - capacity.DiskUsedBytes
		projection := Projection{ThresholdPercent: threshold, TargetUsedBytes: target, RemainingBytes: max(int64(0), remaining)}
		switch {
		case remaining <= 0:
			zero := 0.0
			timestamp := at
			projection.State = "already_exceeded"
			projection.Days = &zero
			projection.EstimatedAt = &timestamp
		case growth.Direction != "growing" || growth.BytesPerSecond <= 0:
			projection.State = "not_projected"
		default:
			days := float64(remaining) / growth.BytesPerSecond / (24 * 60 * 60)
			projection.Days = &days
			if days > maxProjectionDays {
				projection.State = "beyond_horizon"
				break
			}
			timestamp := at.Add(time.Duration(days * float64(24*time.Hour)))
			projection.State = "projected"
			projection.EstimatedAt = &timestamp
		}
		result = append(result, projection)
	}
	return result
}

func percentage(numerator, denominator int64) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator) * 100
}
