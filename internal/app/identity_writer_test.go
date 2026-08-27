package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/report"
)

func TestConsoleIdentitiesGroupByClassification(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	writer, err := newIdentityWriter(report.FormatConsole, &output)
	if err != nil {
		t.Fatalf("newIdentityWriter() error = %v", err)
	}
	identities := []Identity{
		{
			Target:         model.Endpoint{Scheme: model.SchemeHTTP, Host: "192.0.2.20", Port: 9200},
			Classification: "unknown",
			Score:          10,
			Threshold:      80,
		},
		{
			Target:         model.Endpoint{Scheme: model.SchemeHTTP, Host: "192.0.2.10", Port: 9200},
			Product:        "elasticsearch",
			Version:        "8.19.19",
			Classification: "confirmed",
			Score:          95,
			Threshold:      80,
			Detected:       true,
		},
	}
	for _, identity := range identities {
		if writeErr := writer.Write(context.Background(), identity); writeErr != nil {
			t.Fatalf("Write() error = %v", writeErr)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	got := output.String()
	if strings.Contains(got, "\033[") {
		t.Fatalf("buffer output contained ANSI: %q", got)
	}
	confirmed := strings.Index(got, "CONFIRMED")
	unknown := strings.Index(got, "UNKNOWN")
	if confirmed < 0 || unknown < 0 || confirmed > unknown {
		t.Fatalf("classification order is wrong:\n%s", got)
	}
	if !strings.Contains(got, "1 confirmed") || !strings.Contains(got, "1 unknown") {
		t.Fatalf("summary missing counts:\n%s", got)
	}
}
