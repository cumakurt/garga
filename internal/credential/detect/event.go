package detect

import (
	"fmt"
	"strings"

	"github.com/cumakurt/garga/internal/credential"
)

// StopReason explains why a detection run ended. It never contains secret material.
type StopReason string

const (
	StopCompleted   StopReason = "completed"
	StopSuccess     StopReason = "success"
	StopCeiling     StopReason = "attempt_ceiling"
	StopUnavailable StopReason = "security_unavailable"
	StopCanceled    StopReason = "canceled"
	StopRateLimited StopReason = "rate_limited"
)

// OutcomeTransient marks a retryable authenticate response. It is not a credential.Outcome.
const OutcomeTransient credential.Outcome = "transient"

// Event is one secret-free authenticate attempt.
type Event struct {
	Attempt    int
	Mode       Mode
	Host       string
	Port       int
	Username   string
	Mechanism  credential.Kind
	Outcome    credential.Outcome
	StatusCode int
}

// Report is the secret-free result of one explicit detection run.
type Report struct {
	Mode           Mode
	Events         []Event
	StopReason     StopReason
	Attempts       int
	Planned        int
	ValidUsernames []string
}

// FormatEvent writes one redacted detection event line.
func FormatEvent(event Event) string {
	line := fmt.Sprintf(
		"auth-detect: mode=%s attempt=%d host=%s outcome=%s mechanism=%s status=%d",
		event.Mode,
		event.Attempt,
		event.Host,
		event.Outcome,
		event.Mechanism,
		event.StatusCode,
	)
	if event.Username != "" {
		line = fmt.Sprintf(
			"auth-detect: mode=%s attempt=%d host=%s username=%s outcome=%s mechanism=%s status=%d",
			event.Mode,
			event.Attempt,
			event.Host,
			event.Username,
			event.Outcome,
			event.Mechanism,
			event.StatusCode,
		)
	}
	return line
}

// FormatSummary writes the secret-free completion line.
func FormatSummary(report Report) string {
	line := fmt.Sprintf(
		"auth-detect: mode=%s stopped reason=%s attempts=%d planned=%d valid=%d",
		report.Mode,
		report.StopReason,
		report.Attempts,
		report.Planned,
		len(report.ValidUsernames),
	)
	if len(report.ValidUsernames) > 0 {
		line += " usernames=" + strings.Join(report.ValidUsernames, ",")
	}
	return line
}
