package audit

import (
	"fmt"

	"github.com/cumakurt/garga/internal/credential"
)

// StopReason explains why an audit run ended. It never contains secret material.
type StopReason string

const (
	StopCompleted   StopReason = "completed"
	StopSuccess     StopReason = "success"
	StopCeiling     StopReason = "attempt_ceiling"
	StopUnavailable StopReason = "security_unavailable"
	StopCanceled    StopReason = "canceled"
)

// OutcomeTransient marks a retryable authenticate response. It is not a credential.Outcome.
const OutcomeTransient credential.Outcome = "transient"

// Event is one secret-free authenticate attempt.
type Event struct {
	Attempt    int
	Host       string
	Port       int
	Username   string
	Mechanism  credential.Kind
	Outcome    credential.Outcome
	StatusCode int
}

// Report is the secret-free result of one explicit audit run.
type Report struct {
	Events     []Event
	StopReason StopReason
	Attempts   int
}

// FormatEvent writes one redacted audit event line.
func FormatEvent(event Event) string {
	line := fmt.Sprintf(
		"auth-audit: attempt=%d host=%s outcome=%s mechanism=%s status=%d",
		event.Attempt,
		event.Host,
		event.Outcome,
		event.Mechanism,
		event.StatusCode,
	)
	if event.Username != "" {
		line = fmt.Sprintf(
			"auth-audit: attempt=%d host=%s username=%s outcome=%s mechanism=%s status=%d",
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
	return fmt.Sprintf("auth-audit: stopped reason=%s attempts=%d", report.StopReason, report.Attempts)
}
