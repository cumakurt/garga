package checker

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/config"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func percentSeverity(value float64, threshold config.PercentThreshold) healthmodel.Severity {
	switch {
	case value >= threshold.Critical:
		return healthmodel.SeverityCritical
	case value >= threshold.High:
		return healthmodel.SeverityHigh
	case value >= threshold.Warning:
		return healthmodel.SeverityMedium
	default:
		return healthmodel.SeverityOK
	}
}

func percentage(numerator, denominator int64) float64 {
	if denominator <= 0 || numerator < 0 {
		return 0
	}
	return float64(numerator) / float64(denominator) * 100
}

func fixed(value float64) float64 {
	return math.Round(value*100) / 100
}

func stats(values []float64) (mean, median, standardDeviation, coefficientVariation float64) {
	if len(values) == 0 {
		return 0, 0, 0, 0
	}
	copyValues := append([]float64(nil), values...)
	sort.Float64s(copyValues)
	for _, value := range copyValues {
		mean += value
	}
	mean /= float64(len(copyValues))
	if len(copyValues)%2 == 0 {
		median = (copyValues[len(copyValues)/2-1] + copyValues[len(copyValues)/2]) / 2
	} else {
		median = copyValues[len(copyValues)/2]
	}
	for _, value := range copyValues {
		difference := value - mean
		standardDeviation += difference * difference
	}
	standardDeviation = math.Sqrt(standardDeviation / float64(len(copyValues)))
	if mean != 0 {
		coefficientVariation = standardDeviation / mean
	}
	return fixed(mean), fixed(median), fixed(standardDeviation), fixed(coefficientVariation)
}

func parseWatermark(value string) (usedPercent float64, freeBytes int64, percentage, ok bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.HasSuffix(value, "%") {
		parsed, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(value, "%")), 64)
		return parsed, 0, true, err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0) && parsed >= 0 && parsed <= 100
	}
	if parsed, err := strconv.ParseFloat(value, 64); err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0) && parsed >= 0 && parsed <= 1 {
		return parsed * 100, 0, true, true
	}
	bytes, valid := parseElasticsearchBytes(value)
	return 0, bytes, false, valid
}

func parseElasticsearchBytes(value string) (int64, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	units := []struct {
		suffix string
		factor float64
	}{
		{"pib", 1 << 50}, {"pb", 1 << 50}, {"pi", 1 << 50}, {"p", 1 << 50},
		{"tib", 1 << 40}, {"tb", 1 << 40}, {"ti", 1 << 40}, {"t", 1 << 40},
		{"gib", 1 << 30}, {"gb", 1 << 30}, {"gi", 1 << 30}, {"g", 1 << 30},
		{"mib", 1 << 20}, {"mb", 1 << 20}, {"mi", 1 << 20}, {"m", 1 << 20},
		{"kib", 1 << 10}, {"kb", 1 << 10}, {"ki", 1 << 10}, {"k", 1 << 10},
		{"b", 1},
	}
	for _, unit := range units {
		if !strings.HasSuffix(value, unit.suffix) {
			continue
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(value, unit.suffix)), 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed < 0 || parsed > float64(math.MaxInt64)/unit.factor {
			return 0, false
		}
		return int64(parsed * unit.factor), true
	}
	return 0, false
}

func watermarkRequiredFree(totalBytes int64, value, maxHeadroom string) (int64, bool) {
	percent, freeBytes, percentage, ok := parseWatermark(value)
	if !ok {
		return 0, false
	}
	if !percentage {
		return freeBytes, true
	}
	required := int64(float64(totalBytes) * (100 - percent) / 100)
	if headroom, valid := parseElasticsearchBytes(maxHeadroom); valid && required > headroom {
		required = headroom
	}
	return required, true
}

func watermarkExceeded(totalBytes, availableBytes int64, value, maxHeadroom string) bool {
	required, ok := watermarkRequiredFree(totalBytes, value, maxHeadroom)
	return ok && availableBytes <= required
}

func collectionSucceeded(snapshot *healthmodel.ClusterSnapshot, name string) bool {
	for _, result := range snapshot.Collection.Collectors {
		if result.Name == name && result.Status == "success" {
			return true
		}
	}
	return false
}

func baselineNode(snapshot *healthmodel.ClusterSnapshot, node healthmodel.Node) (healthmodel.NodeCounters, time.Duration, bool) {
	if snapshot.Baseline == nil || snapshot.Baseline.ClusterUUID != snapshot.Cluster.UUID || !snapshot.Timestamp.After(snapshot.Baseline.Timestamp) {
		return healthmodel.NodeCounters{}, 0, false
	}
	previous, ok := snapshot.Baseline.Nodes[node.ID]
	return previous, snapshot.Timestamp.Sub(snapshot.Baseline.Timestamp), ok
}

func counterDelta(current, previous int64) (int64, bool) {
	if current < previous {
		return 0, false
	}
	return current - previous, true
}

func thresholdText(threshold config.PercentThreshold) string {
	return fmt.Sprintf("warning %.0f%%, high %.0f%%, critical %.0f%%", threshold.Warning, threshold.High, threshold.Critical)
}

func productionLike(profile config.HealthProfile) bool {
	return !availabilityLenient(profile)
}

func availabilityLenient(profile config.HealthProfile) bool {
	return profile == config.HealthProfileDevelopment || profile == config.HealthProfileSmall
}

func strictAnonymous(profile config.HealthProfile) bool {
	return profile == config.HealthProfileSecurity || profile == config.HealthProfileProduction
}

func largeTopology(profile config.HealthProfile) bool {
	return profile == config.HealthProfileLarge
}

func searchSensitive(profile config.HealthProfile) bool {
	return profile == config.HealthProfileSearch
}

func variationForProfile(threshold config.VariationThreshold, profile config.HealthProfile) config.VariationThreshold {
	if !largeTopology(profile) {
		return threshold
	}
	return config.VariationThreshold{Warning: threshold.Warning * 0.8, High: threshold.High * 0.8}
}
