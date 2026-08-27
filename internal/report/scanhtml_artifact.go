package report

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cumakurt/garga/internal/model"
)

// HTMLArtifactWriter buffers findings and writes a detailed timestamped HTML
// report to the current directory when Close is called.
type HTMLArtifactWriter struct {
	primary        Writer
	notice         io.Writer
	scannerVersion string
	started        time.Time

	mu       sync.Mutex
	items    []model.Finding
	coverage ProbeCoverage
	closed   bool
}

// WithHTMLArtifact copies each finding to primary and, on Close, writes a
// standalone HTML assessment in the working directory. Machine stdout format
// is unchanged. The path is printed to notice when set.
func WithHTMLArtifact(primary Writer, notice io.Writer, scannerVersion string) *HTMLArtifactWriter {
	return &HTMLArtifactWriter{
		primary:        primary,
		notice:         notice,
		scannerVersion: scannerVersion,
		started:        time.Now(),
	}
}

func (writer *HTMLArtifactWriter) Write(ctx context.Context, finding model.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	writer.mu.Lock()
	if writer.closed {
		writer.mu.Unlock()
		return errWriterClosed
	}
	writer.items = append(writer.items, prepared(finding))
	writer.mu.Unlock()
	if writer.primary == nil {
		return nil
	}
	return writer.primary.Write(ctx, finding)
}

// SetCoverage records probe telemetry included in the HTML executive summary.
func (writer *HTMLArtifactWriter) SetCoverage(coverage ProbeCoverage) {
	if writer == nil {
		return
	}
	writer.mu.Lock()
	writer.coverage = coverage
	writer.mu.Unlock()
}

func (writer *HTMLArtifactWriter) Close() error {
	writer.mu.Lock()
	if writer.closed {
		writer.mu.Unlock()
		return nil
	}
	writer.closed = true
	items := append([]model.Finding(nil), writer.items...)
	coverage := writer.coverage
	if coverage.Duration <= 0 && !writer.started.IsZero() {
		coverage.Duration = time.Since(writer.started)
	}
	writer.mu.Unlock()

	var closeErr error
	if writer.primary != nil {
		closeErr = writer.primary.Close()
	}
	artifactErr := writer.writeArtifact(items, coverage)
	if closeErr != nil {
		return closeErr
	}
	return artifactErr
}

func (writer *HTMLArtifactWriter) writeArtifact(items []model.Finding, coverage ProbeCoverage) error {
	if len(items) == 0 && coverage.Submitted == 0 {
		return nil
	}
	path, err := WriteTimestampedScanHTML(items, coverage, writer.scannerVersion)
	if err != nil {
		return err
	}
	if writer.notice == nil {
		return nil
	}
	if _, err := fmt.Fprintf(writer.notice, "garga: HTML scan report written to %s\n", path); err != nil {
		return fmt.Errorf("write scan report notice: %w", err)
	}
	return nil
}

// WriteTimestampedScanHTML writes a complete standalone HTML assessment to the
// current directory. The final name includes a UTC timestamp and a random suffix.
func WriteTimestampedScanHTML(findings []model.Finding, coverage ProbeCoverage, scannerVersion string) (path string, err error) {
	generated := time.Now().UTC()
	prefix := ".garga-scan-" + generated.Format("20060102T150405.000Z") + "-"
	temporary, err := os.CreateTemp(".", prefix+"*.tmp")
	if err != nil {
		return "", fmt.Errorf("create timestamped scan report: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		return "", fmt.Errorf("secure timestamped scan report: %w", err)
	}
	document := buildScanHTMLDocument(findings, coverage, scannerVersion, generated)
	if err = writeScanHTML(temporary, document); err != nil {
		return "", err
	}
	if err = temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync timestamped scan report: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return "", fmt.Errorf("close timestamped scan report: %w", err)
	}
	base := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(temporaryPath), "."), ".tmp") + ".html"
	finalPath := filepath.Join(filepath.Dir(temporaryPath), base)
	if err = os.Rename(temporaryPath, finalPath); err != nil {
		return "", fmt.Errorf("activate timestamped scan report: %w", err)
	}
	absolute, absoluteErr := filepath.Abs(finalPath)
	if absoluteErr != nil {
		return finalPath, nil
	}
	return absolute, nil
}
