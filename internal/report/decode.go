package report

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/cumakurt/garga/internal/model"
)

// MaxFindingLineBytes is the maximum size of one JSONL finding record.
const MaxFindingLineBytes = 1 << 20

// DecodeJSONL reads one finding JSON object per line and never retains the scan.
func DecodeJSONL(ctx context.Context, reader io.Reader, emit func(model.Finding) error) error {
	if reader == nil {
		return fmt.Errorf("decode finding: input is required")
	}
	if emit == nil {
		return fmt.Errorf("decode finding: emit callback is required")
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxFindingLineBytes)
	lineNumber := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var finding model.Finding
		if err := json.Unmarshal(line, &finding); err != nil {
			return fmt.Errorf("decode finding: line %d is not a valid JSON object", lineNumber)
		}
		if finding.CheckID == "" {
			return fmt.Errorf("decode finding: line %d is missing check_id", lineNumber)
		}
		if err := emit(finding); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("decode finding: a record exceeds the %d-byte line limit", MaxFindingLineBytes)
		}
		return fmt.Errorf("decode finding: read input: %w", err)
	}
	return nil
}
