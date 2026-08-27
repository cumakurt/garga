package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestFormatIsDeterministicAndHostFree(t *testing.T) {
	t.Parallel()

	snapshot := Snapshot{Submitted: 1024, Completed: 384, Succeeded: 12, Failed: 372}
	elapsed := 8 * time.Second
	first := Format(snapshot, elapsed, false, true)
	second := Format(snapshot, elapsed, false, true)
	if first != second {
		t.Fatalf("Format is not deterministic: %q vs %q", first, second)
	}
	if !strings.Contains(first, "384/1024") || !strings.Contains(first, "37%") {
		t.Fatalf("Format = %q", first)
	}
	if !strings.Contains(first, "ok 12") || !strings.Contains(first, "fail 372") {
		t.Fatalf("Format missing outcome counts: %q", first)
	}
	if !strings.Contains(first, "48/s") || !strings.Contains(first, "eta 13s") {
		t.Fatalf("Format missing rate/eta: %q", first)
	}
	if strings.Contains(first, "http") || strings.Contains(first, "192.") || strings.Contains(first, "example") {
		t.Fatalf("Format leaked a host: %q", first)
	}
	if strings.ContainsAny(first, "\n\r") {
		t.Fatalf("Format included a newline: %q", first)
	}
	if !strings.Contains(first, "#") || !strings.Contains(first, "-") {
		t.Fatalf("ASCII bar missing: %q", first)
	}
}

func TestFormatUnicodeBar(t *testing.T) {
	t.Parallel()

	line := Format(Snapshot{Submitted: 10, Completed: 10}, time.Second, false, false)
	if !strings.Contains(line, "█") || strings.Contains(line, "#") {
		t.Fatalf("unicode bar = %q", line)
	}
	if !strings.Contains(line, "10/10") || !strings.Contains(line, "100%") {
		t.Fatalf("complete bar = %q", line)
	}
}

func TestBarForceWritesAndClears(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	bar := Open(&output, Options{Force: true})
	bar.started = time.Now().Add(-time.Second)
	bar.Record(Snapshot{Submitted: 20, Completed: 5, Succeeded: 4, Failed: 1})
	if !strings.Contains(output.String(), "\r") || !strings.Contains(output.String(), "5/20") {
		t.Fatalf("bar output = %q", output.String())
	}
	if err := bar.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !strings.HasSuffix(output.String(), "\r") {
		t.Fatalf("Close() did not return to column 0: %q", output.String())
	}
	if err := bar.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestBarDisabledOnNonTerminal(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	bar := Open(&output, Options{})
	bar.Record(Snapshot{Submitted: 100, Completed: 50})
	if err := bar.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("non-terminal output = %q", output.String())
	}
}

func TestShouldShowThresholds(t *testing.T) {
	t.Parallel()

	if shouldShow(Snapshot{}, 0) {
		t.Fatal("empty snapshot should stay hidden")
	}
	if shouldShow(Snapshot{Submitted: 1, Completed: 0}, 100*time.Millisecond) {
		t.Fatal("fast single target should stay hidden")
	}
	if !shouldShow(Snapshot{Submitted: 8, Completed: 1}, 0) {
		t.Fatal("batch of 8 should show immediately")
	}
	if !shouldShow(Snapshot{Submitted: 1, Completed: 0}, minElapsedToShow) {
		t.Fatal("slow probe should show after delay")
	}
}
