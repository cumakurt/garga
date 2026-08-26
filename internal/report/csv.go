package report

import (
	"context"
	"encoding/csv"
	"io"
	"strings"

	"github.com/cumakurt/garga/internal/model"
)

var csvHeader = []string{
	"schema_version",
	"id",
	"check_id",
	"title",
	"severity",
	"confidence",
	"product",
	"version",
	"target",
	"resource",
	"cve",
	"tags",
	"evidence",
	"remediation",
}

type csvWriter struct {
	output  *csv.Writer
	started bool
	closed  bool
}

func newCSVWriter(output io.Writer) *csvWriter {
	return &csvWriter{output: csv.NewWriter(output)}
}

func (writer *csvWriter) Write(ctx context.Context, finding model.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if writer.closed {
		return errWriterClosed
	}
	if !writer.started {
		if err := writer.output.Write(csvHeader); err != nil {
			return err
		}
		writer.started = true
	}
	finding = prepared(finding)
	codes := evidenceCodes(finding)
	record := []string{
		safeCSV(finding.SchemaVersion),
		safeCSV(finding.ID),
		safeCSV(finding.CheckID),
		safeCSV(finding.Title),
		safeCSV(string(finding.Severity)),
		safeCSV(string(finding.Confidence)),
		safeCSV(finding.Product),
		safeCSV(finding.Version),
		safeCSV(targetDisplay(finding.Target)),
		safeCSV(finding.Resource),
		safeCSV(strings.Join(finding.CVE, " ")),
		safeCSV(strings.Join(finding.Tags, " ")),
		safeCSV(strings.Join(codes, " ")),
		safeCSV(finding.Remediation),
	}
	if err := writer.output.Write(record); err != nil {
		return err
	}
	writer.output.Flush()
	return writer.output.Error()
}

func (writer *csvWriter) Close() error {
	if writer.closed {
		return nil
	}
	writer.closed = true
	if !writer.started {
		if err := writer.output.Write(csvHeader); err != nil {
			return err
		}
	}
	writer.output.Flush()
	return writer.output.Error()
}

func safeCSV(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	default:
		return value
	}
}
