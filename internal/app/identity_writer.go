package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/cumakurt/garga/internal/report"
)

type identityWriter interface {
	Write(ctx context.Context, identity Identity) error
	Close() error
}

func newIdentityWriter(format report.Format, output io.Writer) (identityWriter, error) {
	if output == nil {
		return nil, internalError("output is required", nil)
	}
	switch format {
	case report.FormatConsole:
		return &consoleIdentityWriter{output: output}, nil
	case report.FormatJSON:
		return &jsonIdentityWriter{output: output}, nil
	case report.FormatJSONL:
		return &jsonlIdentityWriter{output: output}, nil
	default:
		return nil, invalidError("fingerprint format is not supported", nil)
	}
}

type consoleIdentityWriter struct {
	output io.Writer
}

func (writer *consoleIdentityWriter) Write(ctx context.Context, identity Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target := identity.Target.Host
	if rawURL, err := identity.Target.URL(); err == nil {
		target = rawURL
	}
	product := identity.Product
	if product == "" {
		product = "-"
	}
	version := identity.Version
	if version == "" {
		version = "-"
	}
	_, err := fmt.Fprintf(
		writer.output,
		"%s  classification=%s score=%d detected=%t  %s %s\n",
		target,
		identity.Classification,
		identity.Score,
		identity.Detected,
		product,
		version,
	)
	return err
}

func (writer *consoleIdentityWriter) Close() error {
	return nil
}

type jsonlIdentityWriter struct {
	output io.Writer
}

func (writer *jsonlIdentityWriter) Write(ctx context.Context, identity Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoder := json.NewEncoder(writer.output)
	encoder.SetEscapeHTML(true)
	return encoder.Encode(identity)
}

func (writer *jsonlIdentityWriter) Close() error {
	return nil
}

type jsonIdentityWriter struct {
	output io.Writer
	count  int
	closed bool
}

func (writer *jsonIdentityWriter) Write(ctx context.Context, identity Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if writer.closed {
		return internalError("write identity", nil)
	}
	payload, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	if writer.count == 0 {
		header := `{"schema_version":"` + identitySchemaVersion + `","identities":[`
		if _, err := io.WriteString(writer.output, header); err != nil {
			return err
		}
	} else if _, err := io.WriteString(writer.output, ","); err != nil {
		return err
	}
	if _, err := writer.output.Write(payload); err != nil {
		return err
	}
	writer.count++
	return nil
}

func (writer *jsonIdentityWriter) Close() error {
	if writer.closed {
		return nil
	}
	writer.closed = true
	if writer.count == 0 {
		_, err := io.WriteString(writer.output, `{"schema_version":"`+identitySchemaVersion+`","identities":[]}`+"\n")
		return err
	}
	_, err := io.WriteString(writer.output, "]}\n")
	return err
}
