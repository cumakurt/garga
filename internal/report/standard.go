package report

import (
	"fmt"
	"sort"

	"github.com/cumakurt/garga/internal/model"
)

const maxStandardFindings = 100_000

type standardBuffer struct {
	findings []model.Finding
	closed   bool
}

func (buffer *standardBuffer) add(finding model.Finding) error {
	if buffer.closed {
		return errWriterClosed
	}
	if len(buffer.findings) >= maxStandardFindings {
		return fmt.Errorf("standard report exceeds %d findings", maxStandardFindings)
	}
	buffer.findings = append(buffer.findings, prepared(finding))
	return nil
}

func (buffer *standardBuffer) finish() []model.Finding {
	buffer.closed = true
	sort.SliceStable(buffer.findings, func(left, right int) bool {
		if buffer.findings[left].CheckID != buffer.findings[right].CheckID {
			return buffer.findings[left].CheckID < buffer.findings[right].CheckID
		}
		if buffer.findings[left].ID != buffer.findings[right].ID {
			return buffer.findings[left].ID < buffer.findings[right].ID
		}
		leftURL, _ := buffer.findings[left].Target.URL()
		rightURL, _ := buffer.findings[right].Target.URL()
		return leftURL < rightURL
	})
	return buffer.findings
}
