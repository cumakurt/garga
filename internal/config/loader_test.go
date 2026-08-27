package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoaderAppliesPrecedence(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
scanner:
  concurrency: 30
  requests_per_second: 60
  per_host_requests_per_second: 6
  connect_timeout: 3s
  request_timeout: 6s
  retries: 2
  max_response_bytes: 600000
fingerprint:
  threshold: 70
output:
  format: json
logging:
  level: warn
`)
	environment := map[string]string{
		"GARGA_CONCURRENCY":           "40",
		"GARGA_RATE":                  "70",
		"GARGA_PER_HOST_RATE":         "7",
		"GARGA_CONNECT_TIMEOUT":       "4s",
		"GARGA_REQUEST_TIMEOUT":       "7s",
		"GARGA_RETRIES":               "3",
		"GARGA_MAX_RESPONSE_BYTES":    "700000",
		"GARGA_FINGERPRINT_THRESHOLD": "75",
		"GARGA_OUTPUT_FORMAT":         "csv",
		"GARGA_LOG_LEVEL":             "error",
	}
	overrides := Overrides{
		Concurrency:       ptr(50),
		RequestsPerSecond: ptr(80.0),
		PerHostRate:       ptr(8.0),
		ConnectTimeout:    ptr(5 * time.Second),
		RequestTimeout:    ptr(8 * time.Second),
		Retries:           ptr(4),
		MaxResponseBytes:  ptr(int64(800000)),
		FingerprintScore:  ptr(85),
		OutputFormat:      ptr(OutputHTML),
		LogLevel:          ptr(LogDebug),
	}

	got, err := NewLoader(mapLookup(environment)).Load(Options{ConfigPath: path, Overrides: overrides})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := Config{
		Scanner: ScannerConfig{
			Concurrency:       50,
			RequestsPerSecond: 80,
			PerHostRate:       8,
			ConnectTimeout:    5 * time.Second,
			RequestTimeout:    8 * time.Second,
			Retries:           4,
			MaxResponseBytes:  800000,
		},
		Fingerprint: FingerprintConfig{Threshold: 85},
		Health:      Defaults().Health,
		Output:      OutputConfig{Format: OutputHTML},
		Logging:     LoggingConfig{Level: LogDebug},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestLoaderAppliesHealthThresholds(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
health:
  profile: logging
  concurrency: 3
  requests_per_second: 4
  top_n: 7
  max_response_bytes: 67108864
  thresholds:
    jvm:
      warning: 70
      high: 80
      critical: 90
    shard_size:
      small: 500MB
      large_warning: 60GB
      large_high: 120GB
    pending_task_warning: 45s
    pending_task_high: 3m
`)
	got, err := NewLoader(mapLookup(nil)).Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Health.Profile != HealthProfileLogging || got.Health.Concurrency != 3 || got.Health.RequestsPerSecond != 4 || got.Health.TopN != 7 || got.Health.MaxResponseBytes != 67108864 {
		t.Fatalf("health settings = %#v", got.Health)
	}
	if got.Health.Thresholds.JVM != (PercentThreshold{Warning: 70, High: 80, Critical: 90}) {
		t.Fatalf("JVM thresholds = %#v", got.Health.Thresholds.JVM)
	}
	if got.Health.Thresholds.ShardSize.Small != 500_000_000 || got.Health.Thresholds.ShardSize.LargeWarning != 60_000_000_000 || got.Health.Thresholds.ShardSize.LargeHigh != 120_000_000_000 {
		t.Fatalf("shard thresholds = %#v", got.Health.Thresholds.ShardSize)
	}
	if got.Health.Thresholds.PendingTaskWarning != 45*time.Second || got.Health.Thresholds.PendingTaskHigh != 3*time.Minute {
		t.Fatalf("pending task thresholds = %#v", got.Health.Thresholds)
	}
}

func TestCommittedExampleConfigLoads(t *testing.T) {
	t.Parallel()

	got, err := NewLoader(mapLookup(nil)).Load(Options{ConfigPath: filepath.Join("..", "..", "garga.example.yaml")})
	if err != nil {
		t.Fatalf("Load(garga.example.yaml) error = %v", err)
	}
	if got.Health.Profile != HealthProfileStandard || got.Health.Thresholds.Memory.Warning != 90 || got.Health.MaxResponseBytes != 33554432 {
		t.Fatalf("example health config = %#v", got.Health)
	}
}

func TestLoaderPreservesDefaultsForOmittedValues(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "scanner:\n  concurrency: 7\n")
	got, err := NewLoader(mapLookup(nil)).Load(Options{ConfigPath: path})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := Defaults()
	want.Scanner.Concurrency = 7
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestLoaderUsesEnvironmentConfigPath(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "output:\n  format: jsonl\n")
	got, err := NewLoader(mapLookup(map[string]string{"GARGA_CONFIG": path})).Load(Options{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Output.Format != OutputJSONL {
		t.Fatalf("output format = %q, want %q", got.Output.Format, OutputJSONL)
	}
}

func TestExplicitConfigPathOverridesEnvironmentPath(t *testing.T) {
	t.Parallel()

	explicitPath := writeConfig(t, "output:\n  format: csv\n")
	environmentPath := writeConfig(t, "output:\n  format: json\n")
	got, err := NewLoader(mapLookup(map[string]string{"GARGA_CONFIG": environmentPath})).Load(Options{ConfigPath: explicitPath})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Output.Format != OutputCSV {
		t.Fatalf("output format = %q, want %q", got.Output.Format, OutputCSV)
	}
}

func TestLoaderRejectsInvalidEnvironmentWithoutExposingValue(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	tests := []string{
		"GARGA_CONCURRENCY",
		"GARGA_RATE",
		"GARGA_PER_HOST_RATE",
		"GARGA_CONNECT_TIMEOUT",
		"GARGA_REQUEST_TIMEOUT",
		"GARGA_RETRIES",
		"GARGA_MAX_RESPONSE_BYTES",
		"GARGA_FINGERPRINT_THRESHOLD",
		"GARGA_HEALTH_CONCURRENCY",
		"GARGA_HEALTH_RATE",
		"GARGA_HEALTH_TOP_N",
		"GARGA_HEALTH_MAX_RESPONSE_BYTES",
		"GARGA_OUTPUT_FORMAT",
		"GARGA_LOG_LEVEL",
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := NewLoader(mapLookup(map[string]string{name: canary})).Load(Options{})
			if err == nil {
				t.Fatal("Load() returned nil error")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("Load() error exposed canary: %q", err)
			}
			if !strings.Contains(err.Error(), name) && (name != "GARGA_OUTPUT_FORMAT" && name != "GARGA_LOG_LEVEL") {
				t.Fatalf("Load() error = %q, want environment name", err)
			}
		})
	}
}

func TestLoaderRejectsSecretBearingInvalidYAMLWithoutExposingValue(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	tests := map[string]string{
		"unknown field":     "password: " + canary + "\n",
		"wrong scalar type": "scanner:\n  concurrency: " + canary + "\n",
		"invalid duration":  "scanner:\n  connect_timeout: " + canary + "\n",
		"malformed yaml":    "scanner: [" + canary + "\n",
	}

	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := NewLoader(mapLookup(nil)).Load(Options{ConfigPath: writeConfig(t, contents)})
			if err == nil {
				t.Fatal("Load() returned nil error")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("Load() error exposed canary: %q", err)
			}
		})
	}
}

func TestLoaderRejectsMultipleDocuments(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "output:\n  format: json\n---\noutput:\n  format: csv\n")
	_, err := NewLoader(mapLookup(nil)).Load(Options{ConfigPath: path})
	if err == nil || !strings.Contains(err.Error(), "exactly one YAML document") {
		t.Fatalf("Load() error = %v, want single-document error", err)
	}
}

func TestLoaderRejectsOversizedFile(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, strings.Repeat("#", maxConfigFileBytes+1))
	_, err := NewLoader(mapLookup(nil)).Load(Options{ConfigPath: path})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Load() error = %v, want size-limit error", err)
	}
}

func TestLoaderPreservesOpenError(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing.yaml")
	_, err := NewLoader(mapLookup(nil)).Load(Options{ConfigPath: path})
	if err == nil {
		t.Fatal("Load() returned nil error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load() error = %v, want os.ErrNotExist cause", err)
	}
}

func TestLoadUsesProcessEnvironment(t *testing.T) {
	t.Setenv("GARGA_CONCURRENCY", "9")

	got, err := Load(Options{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Scanner.Concurrency != 9 {
		t.Fatalf("concurrency = %d, want 9", got.Scanner.Concurrency)
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "garga.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func ptr[T any](value T) *T {
	return &value
}
