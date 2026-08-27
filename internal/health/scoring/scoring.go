package scoring

import healthmodel "github.com/cumakurt/garga/internal/health/model"

type Result struct {
	Score  int
	Health string
	Counts map[healthmodel.Severity]int
}

// Calculate applies weighted penalties once per root cause so correlated symptoms do not
// artificially collapse the score.
func Calculate(findings []healthmodel.Finding) Result {
	counts := make(map[healthmodel.Severity]int)
	rootSeverity := make(map[string]healthmodel.Severity)
	for _, finding := range findings {
		counts[finding.Severity]++
		root := finding.RootCause
		if root == "" {
			root = finding.StableKey()
		}
		if healthmodel.SeverityRank(finding.Severity) > healthmodel.SeverityRank(rootSeverity[root]) {
			rootSeverity[root] = finding.Severity
		}
	}
	penalty := 0
	for _, severity := range rootSeverity {
		penalty += weight(severity)
	}
	score := 100 - penalty
	if score < 0 {
		score = 0
	}
	return Result{Score: score, Health: healthLabel(score), Counts: counts}
}

func weight(severity healthmodel.Severity) int {
	switch severity {
	case healthmodel.SeverityCritical:
		return 25
	case healthmodel.SeverityHigh:
		return 10
	case healthmodel.SeverityMedium:
		return 5
	case healthmodel.SeverityLow:
		return 2
	default:
		return 0
	}
}

func healthLabel(score int) string {
	switch {
	case score >= 100:
		return "Perfect"
	case score >= 90:
		return "Healthy"
	case score >= 75:
		return "Minor Issues"
	case score >= 50:
		return "Degraded"
	case score >= 25:
		return "High Risk"
	default:
		return "Critical"
	}
}
