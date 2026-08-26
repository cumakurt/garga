package target_test

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/target"
)

func TestDeduplicatingSource(t *testing.T) {
	input := strings.Join([]string{
		"EXAMPLE.org.",
		"example.org",
		"http://EXAMPLE.org",
		"http://example.org:80/",
		"example.org:9200",
	}, "\n")
	reader, err := target.NewReaderSource(strings.NewReader(input), "targets.txt")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	source, err := target.NewDeduplicatingSource(reader, 10)
	if err != nil {
		t.Fatalf("NewDeduplicatingSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	var got []string
	var attributions []string
	for {
		value, err := source.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		got = append(got, value.String())
		attributions = append(attributions, value.Source)
	}

	want := []string{"example.org", "http://example.org:80", "example.org:9200"}
	if !slices.Equal(got, want) {
		t.Errorf("deduplicated targets = %v, want %v", got, want)
	}
	wantAttributions := []string{"targets.txt:1", "targets.txt:3", "targets.txt:5"}
	if !slices.Equal(attributions, wantAttributions) {
		t.Errorf("target attributions = %v, want %v", attributions, wantAttributions)
	}
}

func TestDeduplicatingSourceEnforcesLimit(t *testing.T) {
	reader, err := target.NewReaderSource(strings.NewReader("one.example\ntwo.example\nthree.example\n"), "memory")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	source, err := target.NewDeduplicatingSource(reader, 2)
	if err != nil {
		t.Fatalf("NewDeduplicatingSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	for index := 0; index < 2; index++ {
		if _, err := source.Next(context.Background()); err != nil {
			t.Fatalf("Next() %d error = %v", index, err)
		}
	}
	_, firstErr := source.Next(context.Background())
	if !errors.Is(firstErr, target.ErrDeduplicationLimit) {
		t.Fatalf("Next() error = %v, want ErrDeduplicationLimit", firstErr)
	}
	_, secondErr := source.Next(context.Background())
	if secondErr == nil || secondErr.Error() != firstErr.Error() {
		t.Errorf("deduplication limit error is not terminal: first = %v, second = %v", firstErr, secondErr)
	}
}

func TestDeduplicatingSourceDuplicatesDoNotConsumeCapacity(t *testing.T) {
	reader, err := target.NewReaderSource(strings.NewReader("EXAMPLE.org\nexample.org.\n"), "memory")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	source, err := target.NewDeduplicatingSource(reader, 1)
	if err != nil {
		t.Fatalf("NewDeduplicatingSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	if _, err := source.Next(context.Background()); err != nil {
		t.Fatalf("first Next() error = %v", err)
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Errorf("second Next() error = %v, want io.EOF", err)
	}
}

func TestDeduplicatingSourceCancellationIsResumable(t *testing.T) {
	reader, err := target.NewReaderSource(strings.NewReader("example.org\n"), "memory")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	source, err := target.NewDeduplicatingSource(reader, 1)
	if err != nil {
		t.Fatalf("NewDeduplicatingSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Next(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Next() error = %v, want context.Canceled", err)
	}
	if _, err := source.Next(context.Background()); err != nil {
		t.Fatalf("Next() after cancellation error = %v", err)
	}
}

func TestNewDeduplicatingSourceValidatesArguments(t *testing.T) {
	if _, err := target.NewDeduplicatingSource(nil, 1); err == nil {
		t.Error("NewDeduplicatingSource(nil) error = nil, want failure")
	}
	stub := &stubSource{}
	if _, err := target.NewDeduplicatingSource(stub, 0); err == nil {
		t.Error("NewDeduplicatingSource(limit 0) error = nil, want failure")
	}
}

func TestDeduplicatingSourceClosesWrappedSourceOnce(t *testing.T) {
	closeErr := errors.New("close failed")
	stub := &stubSource{closeErr: closeErr}
	source, err := target.NewDeduplicatingSource(stub, 1)
	if err != nil {
		t.Fatalf("NewDeduplicatingSource() error = %v", err)
	}

	if err := source.Close(); !errors.Is(err, closeErr) {
		t.Errorf("Close() error = %v, want wrapped close error", err)
	}
	if err := source.Close(); err != nil {
		t.Errorf("second Close() error = %v, want nil", err)
	}
	if stub.closeCalls != 1 {
		t.Errorf("wrapped Close() calls = %d, want 1", stub.closeCalls)
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Errorf("Next() after Close error = %v, want io.EOF", err)
	}
}

type stubSource struct {
	targets    []model.Target
	index      int
	closeCalls int
	closeErr   error
}

func (source *stubSource) Next(ctx context.Context) (model.Target, error) {
	if err := ctx.Err(); err != nil {
		return model.Target{}, err
	}
	if source.index >= len(source.targets) {
		return model.Target{}, io.EOF
	}
	value := source.targets[source.index]
	source.index++
	return value, nil
}

func (source *stubSource) Close() error {
	source.closeCalls++
	return source.closeErr
}

var _ target.Source = (*stubSource)(nil)
