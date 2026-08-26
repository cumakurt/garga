package fingerprint

import (
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/config"
)

func TestOptionsFromConfig(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	options, err := OptionsFromConfig(cfg)
	if err != nil {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
	if options.Threshold != cfg.Fingerprint.Threshold {
		t.Fatalf("threshold = %d, want %d", options.Threshold, cfg.Fingerprint.Threshold)
	}
}

func TestOptionsValidation(t *testing.T) {
	t.Parallel()

	for _, threshold := range []int{0, 101} {
		if _, err := New(Options{Threshold: threshold}); err == nil {
			t.Fatalf("New(%d) returned nil error", threshold)
		}
	}
	cfg := config.Defaults()
	cfg.Fingerprint.Threshold = 0
	_, err := OptionsFromConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "fingerprint.threshold") {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
}
