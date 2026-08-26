package report

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/cumakurt/garga/internal/model"
)

type consoleWriter struct {
	output io.Writer
}

func (writer *consoleWriter) Write(ctx context.Context, finding model.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	finding = prepared(finding)
	target := targetDisplay(finding.Target)
	if _, err := fmt.Fprintf(
		writer.output,
		"%s  severity=%s confidence=%s  %s\n%s\n",
		finding.CheckID,
		finding.Severity,
		finding.Confidence,
		target,
		finding.Title,
	); err != nil {
		return err
	}
	if finding.Description != "" {
		if _, err := fmt.Fprintf(writer.output, "  %s\n", finding.Description); err != nil {
			return err
		}
	}
	if codes := evidenceCodes(finding); len(codes) > 0 {
		if _, err := fmt.Fprintf(writer.output, "  evidence: %s\n", strings.Join(codes, ", ")); err != nil {
			return err
		}
	}
	return nil
}

func (writer *consoleWriter) Close() error {
	return nil
}

func targetDisplay(endpoint model.Endpoint) string {
	rawURL, err := endpoint.URL()
	if err != nil {
		return endpoint.Host
	}
	return rawURL
}
