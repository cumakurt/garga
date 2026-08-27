package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
	"github.com/cumakurt/garga/internal/health/redact"
)

func writeJSON(output io.Writer, report healthmodel.Report) error {
	payload, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode health report: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("sanitize health report: %w", err)
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(redact.Value(document)); err != nil {
		return fmt.Errorf("write health report: %w", err)
	}
	return nil
}
