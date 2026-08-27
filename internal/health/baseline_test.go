package health

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func TestSaveAndLoadBaseline(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "baseline.json")
	want := healthmodel.Baseline{
		SchemaVersion: healthmodel.BaselineSchemaVersion, Timestamp: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC), ClusterUUID: "cluster-uuid",
		Nodes: map[string]healthmodel.NodeCounters{"node-1": {QueryTotal: 100}},
	}
	if err := SaveBaseline(path, want, false); err != nil {
		t.Fatalf("SaveBaseline() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("baseline mode = %o, want 600", info.Mode().Perm())
	}
	got, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline() error = %v", err)
	}
	if got.ClusterUUID != want.ClusterUUID || got.Nodes["node-1"].QueryTotal != 100 {
		t.Fatalf("baseline = %#v", got)
	}
	if err := SaveBaseline(path, want, false); err == nil {
		t.Fatal("SaveBaseline() replaced an existing file without overwrite")
	}
	want.ClusterIndices = 42
	if err := SaveBaseline(path, want, true); err != nil {
		t.Fatalf("SaveBaseline(overwrite) error = %v", err)
	}
	replaced, err := LoadBaseline(path)
	if err != nil || replaced.ClusterIndices != 42 {
		t.Fatalf("LoadBaseline() after overwrite = %#v, %v", replaced, err)
	}
}

func TestLoadBaselineRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "baseline.json")
	contents := `{"schema_version":"1.0","timestamp":"2026-08-27T12:00:00Z","cluster_uuid":"uuid","nodes":{},"secret":"credential-canary"}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBaseline(path); err == nil {
		t.Fatal("LoadBaseline() accepted an unknown field")
	}
}
