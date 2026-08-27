package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

// WriteTimestampedHTML writes a complete, standalone HTML report to the current directory.
// The final name includes the scan timestamp and a random collision-resistant suffix.
func WriteTimestampedHTML(report healthmodel.Report) (path string, err error) {
	timestamp := report.Metadata.ScanTimestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	prefix := ".garga-health-" + timestamp.UTC().Format("20060102T150405.000Z") + "-"
	temporary, err := os.CreateTemp(".", prefix+"*.tmp")
	if err != nil {
		return "", fmt.Errorf("create timestamped health report: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		return "", fmt.Errorf("secure timestamped health report: %w", err)
	}
	if err = Write(temporary, FormatHTML, report); err != nil {
		return "", err
	}
	if err = temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync timestamped health report: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return "", fmt.Errorf("close timestamped health report: %w", err)
	}
	base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(temporaryPath), "."), ".tmp") + ".html"
	finalPath := filepath.Join(filepath.Dir(temporaryPath), base)
	if err = os.Rename(temporaryPath, finalPath); err != nil {
		return "", fmt.Errorf("activate timestamped health report: %w", err)
	}
	absolute, absoluteErr := filepath.Abs(finalPath)
	if absoluteErr != nil {
		return finalPath, nil
	}
	return absolute, nil
}
