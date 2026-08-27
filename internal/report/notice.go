package report

import (
	"context"
	"io"

	"github.com/cumakurt/garga/internal/model"
)

type noticeWriter struct {
	primary Writer
	notice  Writer
}

// WithNotice copies each finding to a second writer. Used so CSV/JSON/JSONL/HTML
// still print a human detection summary on the terminal (typically stderr).
func WithNotice(primary Writer, notice io.Writer) Writer {
	if primary == nil || notice == nil {
		return primary
	}
	return &noticeWriter{
		primary: primary,
		notice:  &consoleWriter{output: notice, color: colorEnabled(notice)},
	}
}

func (writer *noticeWriter) Write(ctx context.Context, finding model.Finding) error {
	if err := writer.primary.Write(ctx, finding); err != nil {
		return err
	}
	return writer.notice.Write(ctx, finding)
}

func (writer *noticeWriter) Close() error {
	err := writer.primary.Close()
	noticeErr := writer.notice.Close()
	if err != nil {
		return err
	}
	return noticeErr
}
