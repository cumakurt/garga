package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	t.Parallel()

	if ParseLevel("DEBUG") != slog.LevelDebug {
		t.Fatal("ParseLevel(debug) mismatch")
	}
	if ParseLevel("warn") != slog.LevelWarn {
		t.Fatal("ParseLevel(warn) mismatch")
	}
	if ParseLevel("error") != slog.LevelError {
		t.Fatal("ParseLevel(error) mismatch")
	}
	if ParseLevel("info") != slog.LevelInfo || ParseLevel("other") != slog.LevelInfo {
		t.Fatal("ParseLevel default should be info")
	}
}

func TestLoggerRedactsSecretsAndSensitiveKeys(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	var output bytes.Buffer
	logger := New(&output, slog.LevelInfo, canary)
	logger.Info("password is "+canary, slog.String("authorization", "Bearer "+canary), slog.String("host", "ok.example"))

	payload := output.String()
	if strings.Contains(payload, canary) {
		t.Fatalf("log leaked canary: %s", payload)
	}
	if !strings.Contains(payload, redacted) {
		t.Fatalf("log missing redaction marker: %s", payload)
	}
	if !strings.Contains(payload, "ok.example") {
		t.Fatalf("non-secret attr was removed: %s", payload)
	}
}

func TestBoundedUnknownValuesBecomeOther(t *testing.T) {
	t.Parallel()

	attr := Bounded("error_kind", "credential-canary.example", "timeout", "tls")
	if attr.Value.String() != "other" {
		t.Fatalf("Bounded() = %q, want other", attr.Value.String())
	}
	if Bounded("error_kind", "timeout", "timeout", "tls").Value.String() != "timeout" {
		t.Fatal("Bounded() dropped an allowed value")
	}
}

func TestInfoLoggerOmitsDebugRecords(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	logger := New(&output, slog.LevelInfo)
	logger.Debug("scanner probe attempt", slog.Uint64("sequence", 1))
	logger.Info("scanner started", slog.Int("workers", 20))
	if strings.Contains(output.String(), "scanner probe attempt") {
		t.Fatalf("info logger emitted debug noise: %s", output.String())
	}
	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &record); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; payload = %s", err, output.String())
	}
	if record["msg"] != "scanner started" {
		t.Fatalf("record = %#v", record)
	}
}
