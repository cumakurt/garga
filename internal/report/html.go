package report

import (
	"context"
	"html"
	"io"
	"strings"

	"github.com/cumakurt/garga/internal/model"
)

const htmlHeader = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>garga findings</title>
<style>
body { font-family: sans-serif; margin: 1.5rem; color: #111; background: #fff; }
h1 { font-size: 1.25rem; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #f4f4f4; }
</style>
</head>
<body>
<h1>garga findings</h1>
<p>schema_version ` + model.FindingSchemaVersion + `</p>
<table>
<thead><tr><th>severity</th><th>confidence</th><th>check</th><th>target</th><th>title</th><th>evidence</th></tr></thead>
<tbody>
`

const htmlFooter = `</tbody>
</table>
</body>
</html>
`

type htmlWriter struct {
	output  io.Writer
	started bool
	closed  bool
}

func (writer *htmlWriter) Write(ctx context.Context, finding model.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if writer.closed {
		return errWriterClosed
	}
	if !writer.started {
		if _, err := io.WriteString(writer.output, htmlHeader); err != nil {
			return err
		}
		writer.started = true
	}
	finding = prepared(finding)
	codes := evidenceCodes(finding)
	row := "<tr><td>" + html.EscapeString(string(finding.Severity)) +
		"</td><td>" + html.EscapeString(string(finding.Confidence)) +
		"</td><td>" + html.EscapeString(finding.CheckID) +
		"</td><td>" + html.EscapeString(targetDisplay(finding.Target)) +
		"</td><td>" + html.EscapeString(finding.Title) +
		"</td><td>" + html.EscapeString(strings.Join(codes, ", ")) +
		"</td></tr>\n"
	_, err := io.WriteString(writer.output, row)
	return err
}

func (writer *htmlWriter) Close() error {
	if writer.closed {
		return nil
	}
	writer.closed = true
	if !writer.started {
		if _, err := io.WriteString(writer.output, htmlHeader); err != nil {
			return err
		}
	}
	_, err := io.WriteString(writer.output, htmlFooter)
	return err
}
