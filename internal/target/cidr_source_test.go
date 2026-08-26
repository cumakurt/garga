package target_test

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/target"
)

func TestCIDRSourceIPv4(t *testing.T) {
	source, err := target.NewCIDRSource("192.0.2.3/30", "command-line")
	if err != nil {
		t.Fatalf("NewCIDRSource() error = %v", err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	got := collectTargetStrings(t, source)
	want := []string{"192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"}
	if !slices.Equal(got, want) {
		t.Errorf("CIDR targets = %v, want %v", got, want)
	}
}

func TestCIDRSourceIPv6(t *testing.T) {
	source, err := target.NewCIDRSource("2001:db8::3/126", "command-line")
	if err != nil {
		t.Fatalf("NewCIDRSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	got := collectTargetStrings(t, source)
	want := []string{
		"[2001:db8::]",
		"[2001:db8::1]",
		"[2001:db8::2]",
		"[2001:db8::3]",
	}
	if !slices.Equal(got, want) {
		t.Errorf("CIDR targets = %v, want %v", got, want)
	}
}

func TestCIDRSourcePreservesAttribution(t *testing.T) {
	source, err := target.NewCIDRSource("198.51.100.42/32", "targets.txt:7")
	if err != nil {
		t.Fatalf("NewCIDRSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	got, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error = %v", err)
	}
	if got.Source != "targets.txt:7" {
		t.Errorf("Target.Source = %q, want %q", got.Source, "targets.txt:7")
	}
}

func TestCIDRSourceHugePrefixIsLazy(t *testing.T) {
	source, err := target.NewCIDRSource("::/0", "large-prefix")
	if err != nil {
		t.Fatalf("NewCIDRSource() error = %v", err)
	}

	first, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("first Next() error = %v", err)
	}
	second, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("second Next() error = %v", err)
	}
	if first.Host != "::" || second.Host != "::1" {
		t.Errorf("first two hosts = %q, %q; want ::, ::1", first.Host, second.Host)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Errorf("Next() after Close error = %v, want io.EOF", err)
	}
}

func TestCIDRSourceHandlesMaximumAddresses(t *testing.T) {
	for _, prefix := range []string{"255.255.255.255/32", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"} {
		t.Run(prefix, func(t *testing.T) {
			source, err := target.NewCIDRSource(prefix, "boundary")
			if err != nil {
				t.Fatalf("NewCIDRSource() error = %v", err)
			}
			defer func() { _ = source.Close() }()

			if _, err := source.Next(context.Background()); err != nil {
				t.Fatalf("first Next() error = %v", err)
			}
			if _, err := source.Next(context.Background()); !errors.Is(err, io.EOF) {
				t.Errorf("second Next() error = %v, want io.EOF", err)
			}
		})
	}
}

func TestCIDRSourceCancellationDoesNotConsumeTarget(t *testing.T) {
	source, err := target.NewCIDRSource("203.0.113.0/30", "cancel-test")
	if err != nil {
		t.Fatalf("NewCIDRSource() error = %v", err)
	}
	defer func() { _ = source.Close() }()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Next(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Next() error = %v, want context.Canceled", err)
	}

	got, err := source.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() after cancellation error = %v", err)
	}
	if got.Host != "203.0.113.0" {
		t.Errorf("Next() after cancellation host = %q, want 203.0.113.0", got.Host)
	}
}

func TestNewCIDRSourceRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantMessage string
	}{
		{name: "empty", input: " ", wantMessage: "value is empty"},
		{name: "invalid", input: "secret-invalid-prefix", wantMessage: "invalid IP prefix"},
		{name: "IPv4 bits", input: "192.0.2.0/33", wantMessage: "invalid IP prefix"},
		{name: "IPv6 bits", input: "2001:db8::/129", wantMessage: "invalid IP prefix"},
		{name: "oversized", input: strings.Repeat("a", 8193), wantMessage: "exceeds 8192 bytes"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := target.NewCIDRSource(test.input, "test")
			if err == nil {
				t.Fatal("NewCIDRSource() error = nil, want failure")
			}
			if !strings.Contains(err.Error(), test.wantMessage) {
				t.Errorf("NewCIDRSource() error = %q, want substring %q", err, test.wantMessage)
			}
			if strings.Contains(err.Error(), "secret-invalid-prefix") {
				t.Errorf("NewCIDRSource() leaks rejected input: %q", err)
			}
		})
	}
}

func collectTargetStrings(t *testing.T, source target.Source) []string {
	t.Helper()
	var values []string
	for {
		value, err := source.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return values
		}
		if err != nil {
			t.Fatalf("Next() error = %v", err)
		}
		values = append(values, value.String())
	}
}

var _ target.Source = (*target.CIDRSource)(nil)
