package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

const redacted = "[redacted]"

// ParseLevel maps a configuration log level name to slog.
func ParseLevel(value string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "error":
		return slog.LevelError
	case "warn":
		return slog.LevelWarn
	case "debug":
		return slog.LevelDebug
	default:
		return slog.LevelInfo
	}
}

// New returns a JSON logger that redacts secrets and sensitive attribute names.
func New(output io.Writer, level slog.Level, secrets ...string) *slog.Logger {
	if output == nil {
		output = io.Discard
	}
	handler := slog.NewJSONHandler(output, &slog.HandlerOptions{
		Level:     level,
		AddSource: false,
	})
	return slog.New(&redactingHandler{inner: handler, secrets: compactSecrets(secrets)})
}

type redactingHandler struct {
	inner   slog.Handler
	secrets []string
}

func (handler *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return handler.inner.Enabled(ctx, level)
}

func (handler *redactingHandler) Handle(ctx context.Context, record slog.Record) error {
	rewritten := slog.NewRecord(record.Time, record.Level, redactText(record.Message, handler.secrets), record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		rewritten.AddAttrs(redactAttr(attr, handler.secrets))
		return true
	})
	return handler.inner.Handle(ctx, rewritten)
}

func (handler *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for index, attr := range attrs {
		redacted[index] = redactAttr(attr, handler.secrets)
	}
	return &redactingHandler{inner: handler.inner.WithAttrs(redacted), secrets: handler.secrets}
}

func (handler *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{inner: handler.inner.WithGroup(name), secrets: handler.secrets}
}
