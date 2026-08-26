package cli

import (
	"io"
	"log/slog"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/logging"
)

func newLogger(level config.LogLevel, stderr io.Writer, secrets ...*credential.Secret) *slog.Logger {
	writer := stderr
	if writer == nil {
		writer = io.Discard
	}
	if len(secrets) > 0 {
		writer = secretLogWriter{inner: writer, secrets: secrets}
	}
	return logging.New(writer, logging.ParseLevel(string(level)))
}

type secretLogWriter struct {
	inner   io.Writer
	secrets []*credential.Secret
}

func (writer secretLogWriter) Write(payload []byte) (int, error) {
	text := string(payload)
	for _, secret := range writer.secrets {
		text = credential.Redact(text, secret)
	}
	if _, err := io.WriteString(writer.inner, text); err != nil {
		return 0, err
	}
	return len(payload), nil
}
