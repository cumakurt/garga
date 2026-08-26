package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/logging"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/probe"
)

func TestStatsSummaryHasBoundedFieldsOnly(t *testing.T) {
	t.Parallel()

	summary := Stats{
		Submitted: 3, Started: 3, Attempts: 4, Retries: 1,
		Completed: 3, Succeeded: 2, Failed: 1, Emitted: 3,
		PeakQueueDepth: 2, PeakActiveWorkers: 1, PeakReorderBuffer: 1,
		QueueCapacity: 4, OutstandingWindow: 6,
	}.Summary()
	payload, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if decoded["schema_version"] != summarySchemaVersion || decoded["event"] != summaryEvent {
		t.Fatalf("summary identity = %#v", decoded)
	}
	for _, forbidden := range []string{"host", "url", "target", "path", "authorization", "error"} {
		if _, exists := decoded[forbidden]; exists {
			t.Fatalf("summary includes unbounded field %q: %s", forbidden, payload)
		}
	}
}

func TestEngineInfoLogsOmitPerRequestNoiseAndHosts(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary.example"
	var output bytes.Buffer
	options := scannerTestOptions(t)
	options.Workers = 1
	options.QueueCapacity = 2
	options.Retries = 0
	options.Logger = logging.New(&output, slog.LevelInfo)

	engine := newScannerTestEngine(t, options, successfulProber())
	source := &fixedSource{endpoints: []model.Endpoint{
		{Scheme: model.SchemeHTTPS, Host: canary, Port: 9200},
		{Scheme: model.SchemeHTTPS, Host: canary, Port: 9200},
	}}
	_, err := engine.Run(context.Background(), source, &recordingSink{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("info log lines = %d, want 2 (start+finish); payload = %s", len(lines), output.String())
	}
	if strings.Contains(output.String(), "scanner probe attempt") {
		t.Fatalf("info logs include per-request debug: %s", output.String())
	}
	if strings.Contains(output.String(), canary) {
		t.Fatalf("info logs include host label: %s", output.String())
	}
	var finished map[string]any
	if err := json.Unmarshal(lines[1], &finished); err != nil {
		t.Fatalf("finish record: %v", err)
	}
	if finished["msg"] != "scanner finished" || finished["event"] != summaryEvent {
		t.Fatalf("finish record = %#v", finished)
	}
	if finished["submitted"] != float64(2) || finished["emitted"] != float64(2) {
		t.Fatalf("summary counters = %#v", finished)
	}
}

func TestEngineDebugLogsAttemptsWithoutHosts(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary.example"
	var output bytes.Buffer
	options := scannerTestOptions(t)
	options.Workers = 1
	options.QueueCapacity = 1
	options.Retries = 0
	options.Logger = logging.New(&output, slog.LevelDebug)
	engine := newScannerTestEngine(t, options, probeFunc(func(context.Context, model.Endpoint) (probe.Result, error) {
		return probe.Result{}, &probe.Error{}
	}))
	source := &fixedSource{endpoints: []model.Endpoint{
		{Scheme: model.SchemeHTTPS, Host: canary, Port: 9200},
	}}
	_, err := engine.Run(context.Background(), source, &recordingSink{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if strings.Contains(output.String(), canary) {
		t.Fatalf("debug logs include host: %s", output.String())
	}
	if !strings.Contains(output.String(), "scanner probe attempt") || !strings.Contains(output.String(), "error_kind") {
		t.Fatalf("debug logs missing attempt details: %s", output.String())
	}
}

type fixedSource struct {
	endpoints []model.Endpoint
	index     int
}

func (source *fixedSource) Next(context.Context) (model.Endpoint, error) {
	if source.index >= len(source.endpoints) {
		return model.Endpoint{}, io.EOF
	}
	endpoint := source.endpoints[source.index]
	source.index++
	return endpoint, nil
}

func (source *fixedSource) Close() error { return nil }
