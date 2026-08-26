package target_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/target"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{name: "single", input: "9200", want: []int{9200}},
		{name: "sorted list", input: "9200, 443, 80, 9201", want: []int{80, 443, 9200, 9201}},
		{name: "inclusive range", input: "9200-9203", want: []int{9200, 9201, 9202, 9203}},
		{name: "deduplicated", input: "9200,9199-9201,9200", want: []int{9199, 9200, 9201}},
		{name: "leading zeroes", input: "00080,00443", want: []int{80, 443}},
		{name: "boundary ports", input: "65535,1", want: []int{1, 65535}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := target.ParsePorts(test.input)
			if err != nil {
				t.Fatalf("ParsePorts() error = %v", err)
			}
			if !slices.Equal(got, test.want) {
				t.Errorf("ParsePorts() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestParsePortsRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantMessage string
	}{
		{name: "empty", input: "", wantMessage: "value is empty"},
		{name: "whitespace", input: "  ", wantMessage: "value is empty"},
		{name: "oversized", input: strings.Repeat("1", 8193), wantMessage: "exceeds 8192 bytes"},
		{name: "empty entry", input: "9200,,9201", wantMessage: "empty entry"},
		{name: "trailing comma", input: "9200,", wantMessage: "empty entry"},
		{name: "zero", input: "0", wantMessage: "between 1 and 65535"},
		{name: "above maximum", input: "65536", wantMessage: "between 1 and 65535"},
		{name: "negative", input: "-1", wantMessage: "value is empty"},
		{name: "non-decimal", input: "http", wantMessage: "only decimal digits"},
		{name: "multiple hyphens", input: "1-2-3", wantMessage: "one hyphen"},
		{name: "reversed range", input: "9201-9200", wantMessage: "must not exceed"},
		{name: "empty range end", input: "9200-", wantMessage: "value is empty"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := target.ParsePorts(test.input)
			if err == nil {
				t.Fatal("ParsePorts() error = nil, want failure")
			}
			if !strings.Contains(err.Error(), test.wantMessage) {
				t.Errorf("ParsePorts() error = %q, want substring %q", err, test.wantMessage)
			}
		})
	}
}

func FuzzParsePorts(f *testing.F) {
	for _, seed := range []string{"9200", "80,443,9200-9202", "0", "1-65535", "1-2-3", "\x00"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		ports, err := target.ParsePorts(input)
		if err != nil {
			return
		}
		if len(ports) == 0 {
			t.Fatal("ParsePorts() returned no ports without an error")
		}
		for index, port := range ports {
			if port < target.MinPort || port > target.MaxPort {
				t.Fatalf("ParsePorts() returned out-of-range port %d", port)
			}
			if index > 0 && ports[index-1] >= port {
				t.Fatalf("ParsePorts() result is not sorted and unique: %v", ports)
			}
		}
	})
}
