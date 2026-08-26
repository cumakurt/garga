package target_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/target"
)

func TestReaderSourceParsesTargetsAndCIDRs(t *testing.T) {
	input := strings.Join([]string{
		"  # authorized targets",
		"",
		" EXAMPLE.org. ",
		"192.0.2.2/30",
		"[2001:db8::1]:9200",
		"https://ELASTIC.example.org/elastic",
	}, "\n")
	source, err := target.NewReaderSource(strings.NewReader(input), "targets.txt")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	var gotTargets []string
	var gotSources []string
	for {
		value, err := source.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		gotTargets = append(gotTargets, value.String())
		gotSources = append(gotSources, value.Source)
	}

	wantTargets := []string{
		"example.org",
		"192.0.2.0",
		"192.0.2.1",
		"192.0.2.2",
		"192.0.2.3",
		"[2001:db8::1]:9200",
		"https://elastic.example.org:443/elastic",
	}
	wantSources := []string{
		"targets.txt:3",
		"targets.txt:4",
		"targets.txt:4",
		"targets.txt:4",
		"targets.txt:4",
		"targets.txt:5",
		"targets.txt:6",
	}
	if !slices.Equal(gotTargets, wantTargets) {
		t.Errorf("targets = %v, want %v", gotTargets, wantTargets)
	}
	if !slices.Equal(gotSources, wantSources) {
		t.Errorf("sources = %v, want %v", gotSources, wantSources)
	}
}

func TestReaderSourceUsesDefaultAttribution(t *testing.T) {
	source, err := target.NewReaderSource(strings.NewReader("example.org\n"), "")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	value, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if value.Source != "input:1" {
		t.Errorf("Target.Source = %q, want input:1", value.Source)
	}
}

func TestReaderSourceCancellationDoesNotConsumeInput(t *testing.T) {
	source, err := target.NewReaderSource(strings.NewReader("example.org\n"), "memory")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Next(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Next() error = %v, want context.Canceled", err)
	}
	value, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() after cancellation error = %v", err)
	}
	if value.Host != "example.org" {
		t.Errorf("Next() after cancellation host = %q, want example.org", value.Host)
	}
}

func TestReaderSourceCancellationPausesCIDR(t *testing.T) {
	source, err := target.NewReaderSource(strings.NewReader("198.51.100.0/30\n"), "memory")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	first, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("first Next() error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Next(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Next() error = %v, want context.Canceled", err)
	}
	second, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("second Next() error = %v", err)
	}
	if first.Host != "198.51.100.0" || second.Host != "198.51.100.1" {
		t.Errorf("CIDR hosts = %q, %q; want .0, .1", first.Host, second.Host)
	}
}

func TestReaderSourceRejectsInvalidLines(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantMessage string
	}{
		{name: "inline comment", input: "example.org # comment\n", wantMessage: "memory:1"},
		{name: "invalid CIDR", input: "192.0.2.0/99\n", wantMessage: "invalid CIDR prefix"},
		{name: "oversized line", input: strings.Repeat("a", 10*1024), wantMessage: "too long or unreadable"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source, err := target.NewReaderSource(strings.NewReader(test.input), "memory")
			if err != nil {
				t.Fatalf("NewReaderSource() error = %v", err)
			}
			defer func() { _ = source.Close() }()

			_, firstErr := source.Next(context.Background())
			if firstErr == nil {
				t.Fatal("Next() error = nil, want failure")
			}
			if !strings.Contains(firstErr.Error(), test.wantMessage) {
				t.Errorf("Next() error = %q, want substring %q", firstErr, test.wantMessage)
			}
			_, secondErr := source.Next(context.Background())
			if secondErr == nil || secondErr.Error() != firstErr.Error() {
				t.Errorf("terminal errors differ: first = %v, second = %v", firstErr, secondErr)
			}
		})
	}
}

func TestNewReaderSourceValidatesArguments(t *testing.T) {
	tests := []struct {
		name        string
		reader      io.Reader
		sourceName  string
		wantMessage string
	}{
		{name: "nil reader", reader: nil, sourceName: "memory", wantMessage: "reader is nil"},
		{name: "control in source", reader: strings.NewReader(""), sourceName: "bad\nname", wantMessage: "control characters"},
		{name: "oversized source", reader: strings.NewReader(""), sourceName: strings.Repeat("a", 4097), wantMessage: "exceeds 4096 bytes"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := target.NewReaderSource(test.reader, test.sourceName)
			if err == nil {
				t.Fatal("NewReaderSource() error = nil, want failure")
			}
			if !strings.Contains(err.Error(), test.wantMessage) {
				t.Errorf("NewReaderSource() error = %q, want substring %q", err, test.wantMessage)
			}
		})
	}
}

func TestReaderSourceDoesNotOwnReader(t *testing.T) {
	reader := &trackingReadCloser{Reader: strings.NewReader("example.org\n")}
	source, err := target.NewReaderSource(reader, "memory")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if reader.closed {
		t.Error("Close() closed a reader it does not own")
	}
}

func TestReaderSourceDoesNotReadAheadBeforeDemand(t *testing.T) {
	reader := &countingReader{Reader: strings.NewReader("example.org\n")}
	source, err := target.NewReaderSource(reader, "memory")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	if reader.readCalls != 0 {
		t.Fatalf("reader calls after construction = %d, want 0", reader.readCalls)
	}

	if _, err := source.Next(context.Background()); err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if reader.readCalls == 0 {
		t.Error("Next() did not pull data from the reader")
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestOpenFileSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("example.org\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	source, err := target.OpenFileSource(path)
	if err != nil {
		t.Fatalf("OpenFileSource() error = %v", err)
	}
	value, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if value.Source != path+":1" {
		t.Errorf("Target.Source = %q, want %q", value.Source, path+":1")
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Errorf("Next() after Close error = %v, want io.EOF", err)
	}
	if err := os.Remove(path); err != nil {
		t.Errorf("Remove() after Close error = %v", err)
	}
}

func TestOpenFileSourceReportsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.txt")
	_, err := target.OpenFileSource(path)
	if err == nil {
		t.Fatal("OpenFileSource() error = nil, want failure")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "unable to open") {
		t.Errorf("OpenFileSource() error = %q, want path and actionable context", err)
	}
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

type countingReader struct {
	io.Reader
	readCalls int
}

func (reader *countingReader) Read(buffer []byte) (int, error) {
	reader.readCalls++
	return reader.Reader.Read(buffer)
}

func (reader *trackingReadCloser) Close() error {
	reader.closed = true
	return nil
}

type failingReader struct {
	err error
}

func (reader failingReader) Read(_ []byte) (int, error) {
	return 0, reader.err
}

func TestReaderSourceHandlesReadFailure(t *testing.T) {
	source, err := target.NewReaderSource(failingReader{err: errors.New("read failed")}, "memory")
	if err != nil {
		t.Fatalf("NewReaderSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	if _, err := source.Next(context.Background()); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("Next() error = %v, want unreadable source error", err)
	}
}

func FuzzReaderSource(f *testing.F) {
	for _, seed := range []string{
		"example.org\n",
		"# comment\n192.0.2.0/30\n",
		"::/0\n",
		"https://audit:secret@example.org\n",
		"\x00\xff\n",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		source, err := target.NewReaderSource(strings.NewReader(input), "fuzz")
		if err != nil {
			return
		}
		defer func() { _ = source.Close() }()

		// A valid input can describe an enormous CIDR. Pulling a fixed number proves bounded work.
		for range 32 {
			_, err := source.Next(context.Background())
			if err != nil {
				return
			}
		}
	})
}
