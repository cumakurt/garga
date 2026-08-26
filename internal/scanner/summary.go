package scanner

import "log/slog"

const summarySchemaVersion = "0.1"
const summaryEvent = "scanner.summary"

// Summary is a bounded-cardinality operational record for one engine run.
// It contains counters only: no hosts, URLs, paths, or other user-controlled labels.
type Summary struct {
	SchemaVersion     string `json:"schema_version"`
	Event             string `json:"event"`
	Submitted         uint64 `json:"submitted"`
	Started           uint64 `json:"started"`
	Attempts          uint64 `json:"attempts"`
	Retries           uint64 `json:"retries"`
	Completed         uint64 `json:"completed"`
	Succeeded         uint64 `json:"succeeded"`
	Failed            uint64 `json:"failed"`
	Emitted           uint64 `json:"emitted"`
	PeakQueueDepth    uint64 `json:"peak_queue_depth"`
	PeakActiveWorkers uint64 `json:"peak_active_workers"`
	PeakReorderBuffer uint64 `json:"peak_reorder_buffer"`
	QueueCapacity     int    `json:"queue_capacity"`
	OutstandingWindow int    `json:"outstanding_window"`
}

// Summary returns the schema 0.1 operational summary for this run.
func (stats Stats) Summary() Summary {
	return Summary{
		SchemaVersion:     summarySchemaVersion,
		Event:             summaryEvent,
		Submitted:         stats.Submitted,
		Started:           stats.Started,
		Attempts:          stats.Attempts,
		Retries:           stats.Retries,
		Completed:         stats.Completed,
		Succeeded:         stats.Succeeded,
		Failed:            stats.Failed,
		Emitted:           stats.Emitted,
		PeakQueueDepth:    stats.PeakQueueDepth,
		PeakActiveWorkers: stats.PeakActiveWorkers,
		PeakReorderBuffer: stats.PeakReorderBuffer,
		QueueCapacity:     stats.QueueCapacity,
		OutstandingWindow: stats.OutstandingWindow,
	}
}

func (stats Stats) logAttrs() []any {
	summary := stats.Summary()
	return []any{
		slog.String("schema_version", summary.SchemaVersion),
		slog.String("event", summary.Event),
		slog.Uint64("submitted", summary.Submitted),
		slog.Uint64("started", summary.Started),
		slog.Uint64("attempts", summary.Attempts),
		slog.Uint64("retries", summary.Retries),
		slog.Uint64("completed", summary.Completed),
		slog.Uint64("succeeded", summary.Succeeded),
		slog.Uint64("failed", summary.Failed),
		slog.Uint64("emitted", summary.Emitted),
		slog.Uint64("peak_queue_depth", summary.PeakQueueDepth),
		slog.Uint64("peak_active_workers", summary.PeakActiveWorkers),
		slog.Uint64("peak_reorder_buffer", summary.PeakReorderBuffer),
		slog.Int("queue_capacity", summary.QueueCapacity),
		slog.Int("outstanding_window", summary.OutstandingWindow),
	}
}
