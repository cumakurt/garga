package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

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
		return &consoleIdentityWriter{output: output, color: report.ColorEnabled(output)}, nil
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
	color  bool
	items  []Identity
	closed bool
}

func (writer *consoleIdentityWriter) Write(ctx context.Context, identity Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if writer.closed {
		return internalError("write identity", nil)
	}
	writer.items = append(writer.items, identity)
	return nil
}

func (writer *consoleIdentityWriter) Close() error {
	if writer.closed {
		return nil
	}
	writer.closed = true
	_, err := io.WriteString(writer.output, renderIdentities(writer.items, writer.color))
	return err
}

func renderIdentities(identities []Identity, color bool) string {
	if len(identities) == 0 {
		return "No identities.\n"
	}
	items := append([]Identity(nil), identities...)
	sort.SliceStable(items, func(left, right int) bool {
		if rank := identityRank(items[left].Classification) - identityRank(items[right].Classification); rank != 0 {
			return rank > 0
		}
		return identityTarget(items[left]) < identityTarget(items[right])
	})
	var b strings.Builder
	for index, identity := range items {
		if index > 0 {
			b.WriteByte('\n')
		}
		target := identityTarget(identity)
		b.WriteString(report.Paint(color, "\033[1m\033[36m", target))
		b.WriteByte('\n')
		label := fmt.Sprintf("%-10s", strings.ToUpper(identity.Classification))
		b.WriteString("  ")
		b.WriteString(report.Paint(color, identityColor(identity.Classification), label))
		product := identity.Product
		if product == "" {
			product = "-"
		}
		version := identity.Version
		if version == "" {
			version = "-"
		}
		fmt.Fprintf(&b, " %s %s\n", product, version)
		fmt.Fprintf(&b, "              score %d  threshold %d  detected %t\n", identity.Score, identity.Threshold, identity.Detected)
	}
	b.WriteByte('\n')
	b.WriteString(report.Paint(color, "\033[90m", "────────────────────────────────────────"))
	b.WriteByte('\n')
	b.WriteString(identitySummary(items, color))
	b.WriteByte('\n')
	return b.String()
}

func identityTarget(identity Identity) string {
	if rawURL, err := identity.Target.URL(); err == nil {
		return rawURL
	}
	return identity.Target.Host
}

func identityRank(classification string) int {
	switch classification {
	case "confirmed":
		return 4
	case "likely":
		return 3
	case "possible":
		return 2
	default:
		return 1
	}
}

func identityColor(classification string) string {
	switch classification {
	case "confirmed":
		return "\033[1m\033[32m"
	case "likely":
		return "\033[1m\033[36m"
	case "possible":
		return "\033[1m\033[33m"
	default:
		return "\033[2m"
	}
}

func identitySummary(identities []Identity, color bool) string {
	counts := map[string]int{}
	for _, identity := range identities {
		class := identity.Classification
		if class == "" {
			class = "unknown"
		}
		counts[class]++
	}
	parts := []string{fmt.Sprintf("%d identities", len(identities))}
	for _, class := range []string{"confirmed", "likely", "possible", "unknown"} {
		n := counts[class]
		if n == 0 {
			continue
		}
		parts = append(parts, report.Paint(color, identityColor(class), fmt.Sprintf("%d %s", n, class)))
	}
	return strings.Join(parts, "    ")
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
