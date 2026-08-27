package target_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/target"
)

func TestChainConcatenatesSources(t *testing.T) {
	t.Parallel()

	first, err := target.NewReaderSource(strings.NewReader("127.0.0.1\n"), "cli")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	second, err := target.NewReaderSource(strings.NewReader("192.0.2.1\n"), "file")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	source, err := target.Chain(first, second)
	if err != nil {
		t.Fatalf("Chain() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	got := collectTargets(t, source)
	want := []string{"http://127.0.0.1:9200/", "http://192.0.2.1:9200/"}
	if len(got) != len(want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("targets = %v, want %v", got, want)
		}
	}
}

func TestChainRejectsEmptyAndNil(t *testing.T) {
	t.Parallel()

	if _, err := target.Chain(); err == nil {
		t.Fatal("Chain() succeeded with no sources")
	}
	if _, err := target.Chain(nil); err == nil {
		t.Fatal("Chain() succeeded with a nil source")
	}
}

func collectTargets(t *testing.T, source target.Source) []string {
	t.Helper()
	var values []string
	for {
		next, err := source.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return values
		}
		if err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		endpoint, err := target.Endpoint(next)
		if err != nil {
			t.Fatalf("Endpoint() error = %v", err)
		}
		url, err := endpoint.URL()
		if err != nil {
			t.Fatalf("URL() error = %v", err)
		}
		values = append(values, url)
	}
}
