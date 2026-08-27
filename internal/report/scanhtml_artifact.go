package report

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/pdfdoc"
)

// ArtifactWriter buffers findings and writes timestamped PDF (default) and
// optional HTML reports to the current directory when Close is called.
type ArtifactWriter struct {
	primary        Writer
	notice         io.Writer
	scannerVersion string
	started        time.Time
	pdf            bool
	html           bool

	mu       sync.Mutex
	items    []model.Finding
	coverage ProbeCoverage
	closed   bool
}

// ArtifactOptions selects which CWD report files to write.
type ArtifactOptions struct {
	PDF  bool
	HTML bool
}

// WithArtifacts copies each finding to primary and, on Close, writes selected
// standalone assessments in the working directory. Machine stdout format is unchanged.
func WithArtifacts(primary Writer, notice io.Writer, scannerVersion string, options ArtifactOptions) *ArtifactWriter {
	return &ArtifactWriter{
		primary:        primary,
		notice:         notice,
		scannerVersion: scannerVersion,
		started:        time.Now(),
		pdf:            options.PDF,
		html:           options.HTML,
	}
}

// WithHTMLArtifact writes only the HTML CWD artifact. Prefer WithArtifacts.
func WithHTMLArtifact(primary Writer, notice io.Writer, scannerVersion string) *ArtifactWriter {
	return WithArtifacts(primary, notice, scannerVersion, ArtifactOptions{HTML: true})
}

func (writer *ArtifactWriter) Write(ctx context.Context, finding model.Finding) error {
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

// SetCoverage records probe telemetry included in the executive summary.
func (writer *ArtifactWriter) SetCoverage(coverage ProbeCoverage) {
	if writer == nil {
		return
	}
	writer.mu.Lock()
	writer.coverage = coverage
	writer.mu.Unlock()
}

func (writer *ArtifactWriter) Close() error {
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
	artifactErr := writer.writeArtifacts(items, coverage)
	if closeErr != nil {
		return closeErr
	}
	return artifactErr
}

func (writer *ArtifactWriter) writeArtifacts(items []model.Finding, coverage ProbeCoverage) error {
	if len(items) == 0 && coverage.Submitted == 0 {
		return nil
	}
	if writer.pdf {
		path, err := WriteTimestampedScanPDF(items, coverage, writer.scannerVersion)
		if err != nil {
			return err
		}
		if err := writer.noticePath("PDF scan report written to", path); err != nil {
			return err
		}
	}
	if writer.html {
		path, err := WriteTimestampedScanHTML(items, coverage, writer.scannerVersion)
		if err != nil {
			return err
		}
		if err := writer.noticePath("HTML scan report written to", path); err != nil {
			return err
		}
	}
	return nil
}

func (writer *ArtifactWriter) noticePath(label, path string) error {
	if writer.notice == nil {
		return nil
	}
	if _, err := fmt.Fprintf(writer.notice, "garga: %s %s\n", label, path); err != nil {
		return fmt.Errorf("write scan report notice: %w", err)
	}
	return nil
}

// WriteTimestampedScanHTML writes a complete standalone HTML assessment to the
// current directory. The final name includes a UTC timestamp and a random suffix.
func WriteTimestampedScanHTML(findings []model.Finding, coverage ProbeCoverage, scannerVersion string) (path string, err error) {
	generated := time.Now().UTC()
	prefix := ".garga-scan-" + generated.Format("20060102T150405.000Z") + "-"
	document := buildScanHTMLDocument(findings, coverage, scannerVersion, generated)
	return pdfdoc.WriteCWD(prefix, ".html", "scan HTML", func(output io.Writer) error {
		return writeScanHTML(output, document)
	})
}

// HTMLArtifactWriter is the previous name of ArtifactWriter.
type HTMLArtifactWriter = ArtifactWriter
