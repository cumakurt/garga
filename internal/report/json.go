package report

import (
	"context"
	"encoding/json"
	"io"

	"github.com/cumakurt/garga/internal/model"
)

type jsonWriter struct {
	output io.Writer
	count  int
	closed bool
}

func (writer *jsonWriter) Write(ctx context.Context, finding model.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if writer.closed {
		return errWriterClosed
	}
	payload, err := json.Marshal(prepared(finding))
	if err != nil {
		return err
	}
	if writer.count == 0 {
		header := `{"schema_version":"` + model.FindingSchemaVersion + `","findings":[`
		if _, err := io.WriteString(writer.output, header); err != nil {
			return err
		}
	} else {
		if _, err := io.WriteString(writer.output, ","); err != nil {
			return err
		}
	}
	if _, err := writer.output.Write(payload); err != nil {
		return err
	}
	writer.count++
	return nil
}

func (writer *jsonWriter) Close() error {
	if writer.closed {
		return nil
	}
	writer.closed = true
	if writer.count == 0 {
		_, err := io.WriteString(writer.output, `{"schema_version":"`+model.FindingSchemaVersion+`","findings":[]}`+"\n")
		return err
	}
	_, err := io.WriteString(writer.output, "]}\n")
	return err
}
