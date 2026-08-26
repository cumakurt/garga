package report

import (
	"context"
	"encoding/json"
	"io"

	"github.com/cumakurt/garga/internal/model"
)

type jsonlWriter struct {
	output io.Writer
}

func (writer *jsonlWriter) Write(ctx context.Context, finding model.Finding) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoder := json.NewEncoder(writer.output)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(prepared(finding))
}

func (writer *jsonlWriter) Close() error {
	return nil
}
