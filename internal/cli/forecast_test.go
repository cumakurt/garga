package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/forecast"
	"github.com/cumakurt/garga/internal/health"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func TestForecastCommandWritesJSON(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	start := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	paths := make([]string, 0, 4)
	for index := 0; index < 4; index++ {
		path := filepath.Join(directory, fmt.Sprintf("snapshot-%d.json", index))
		baseline := healthmodel.Baseline{
			SchemaVersion:     healthmodel.BaselineSchemaVersion,
			Timestamp:         start.Add(time.Duration(index) * 24 * time.Hour),
			ClusterUUID:       "cluster-a",
			ClusterStoreBytes: int64(10+index*10) << 30,
			Nodes: map[string]healthmodel.NodeCounters{
				"node-a": {DiskTotalBytes: 100 << 30, DiskAvailableBytes: int64(70-index*10) << 30},
			},
		}
		if err := health.SaveBaseline(path, baseline, false); err != nil {
			t.Fatalf("SaveBaseline() error = %v", err)
		}
		paths = append(paths, path)
	}
	args := append([]string{"forecast", "--format", "json"}, paths...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(context.Background(), args, BuildInfo{}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != ExitSuccess {
		t.Fatalf("exit code = %d; stderr = %q", exitCode, stderr.String())
	}
	var report forecast.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; output = %s", err, stdout.String())
	}
	if report.ClusterUUID != "cluster-a" || report.Samples != 4 || report.Growth.Confidence != "high" {
		t.Fatalf("forecast report = %#v", report)
	}
}

func TestForecastCommandRejectsTooFewSnapshots(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Execute(
		context.Background(), []string{"forecast", "only-one.json"}, BuildInfo{}, strings.NewReader(""), &stdout, &stderr,
	)
	if exitCode != ExitInvalidInput {
		t.Fatalf("exit code = %d, want %d; stderr = %q", exitCode, ExitInvalidInput, stderr.String())
	}
}
