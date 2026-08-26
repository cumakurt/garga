package target_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/target"
)

func TestParse(t *testing.T) {
	const source = "test-fixture"
	tests := []struct {
		name      string
		input     string
		want      model.Target
		canonical string
	}{
		{
			name:  "IPv4",
			input: " 192.168.1.10 ",
			want: model.Target{
				Host:   "192.168.1.10",
				Source: source,
			},
			canonical: "192.168.1.10",
		},
		{
			name:  "IPv4 with port",
			input: "192.168.1.10:09200",
			want: model.Target{
				Host:   "192.168.1.10",
				Port:   9200,
				Source: source,
			},
			canonical: "192.168.1.10:9200",
		},
		{
			name:  "canonical hostname",
			input: "Elastic.Example.ORG.",
			want: model.Target{
				Host:   "elastic.example.org",
				Source: source,
			},
			canonical: "elastic.example.org",
		},
		{
			name:  "single label hostname",
			input: "LOCALHOST:9200",
			want: model.Target{
				Host:   "localhost",
				Port:   9200,
				Source: source,
			},
			canonical: "localhost:9200",
		},
		{
			name:  "HTTP URL default port",
			input: "http://EXAMPLE.ORG/",
			want: model.Target{
				Host:       "example.org",
				Port:       80,
				SchemeHint: model.SchemeHTTP,
				Source:     source,
			},
			canonical: "http://example.org:80",
		},
		{
			name:  "HTTPS URL with path",
			input: "HTTPS://Elastic.Example.org:9243/es/%2fstatus",
			want: model.Target{
				Host:       "elastic.example.org",
				Port:       9243,
				SchemeHint: model.SchemeHTTPS,
				Path:       "/es/%2Fstatus",
				Source:     source,
			},
			canonical: "https://elastic.example.org:9243/es/%2Fstatus",
		},
		{
			name:  "unbracketed IPv6",
			input: "2001:0db8:0:0:0:0:0:1",
			want: model.Target{
				Host:   "2001:db8::1",
				Source: source,
			},
			canonical: "[2001:db8::1]",
		},
		{
			name:  "bracketed IPv6 with port",
			input: "[2001:0db8::1]:9200",
			want: model.Target{
				Host:   "2001:db8::1",
				Port:   9200,
				Source: source,
			},
			canonical: "[2001:db8::1]:9200",
		},
		{
			name:  "bracketed IPv6 without port",
			input: "[2001:db8::1]",
			want: model.Target{
				Host:   "2001:db8::1",
				Source: source,
			},
			canonical: "[2001:db8::1]",
		},
		{
			name:  "IPv6 zone with port",
			input: "[fe80::1%eth0]:9200",
			want: model.Target{
				Host:   "fe80::1%eth0",
				Port:   9200,
				Source: source,
			},
			canonical: "[fe80::1%eth0]:9200",
		},
		{
			name:  "IPv6 zone URL",
			input: "https://[fe80::1%25eth0]:9200/elastic",
			want: model.Target{
				Host:       "fe80::1%eth0",
				Port:       9200,
				SchemeHint: model.SchemeHTTPS,
				Path:       "/elastic",
				Source:     source,
			},
			canonical: "https://[fe80::1%25eth0]:9200/elastic",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := target.Parse(test.input, source)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got != test.want {
				t.Errorf("Parse() = %#v, want %#v", got, test.want)
			}
			if canonical := got.String(); canonical != test.canonical {
				t.Errorf("Target.String() = %q, want %q", canonical, test.canonical)
			}
		})
	}
}

func TestParseRejectsInvalidTargets(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantMessage string
	}{
		{name: "empty", input: "  ", wantMessage: "value is empty"},
		{name: "oversized", input: strings.Repeat("a", 8193), wantMessage: "exceeds 8192 bytes"},
		{name: "unsupported scheme", input: "ftp://example.org", wantMessage: "scheme must be http or https"},
		{name: "missing URL host", input: "http:///elastic", wantMessage: "URL host is required"},
		{name: "URL user information", input: "http://audit:secret@example.org", wantMessage: "user information is not allowed"},
		{name: "URL query", input: "http://example.org?pretty", wantMessage: "query parameters are not supported"},
		{name: "empty URL query", input: "http://example.org?", wantMessage: "query parameters are not supported"},
		{name: "URL fragment", input: "http://example.org#details", wantMessage: "fragments are not supported"},
		{name: "empty URL fragment", input: "http://example.org#", wantMessage: "fragments are not supported"},
		{name: "invalid URL port", input: "http://example.org:invalid", wantMessage: "invalid URL"},
		{name: "empty URL port", input: "http://example.org:", wantMessage: "URL port is empty"},
		{name: "port zero", input: "example.org:0", wantMessage: "between 1 and 65535"},
		{name: "port above maximum", input: "example.org:65536", wantMessage: "between 1 and 65535"},
		{name: "non-decimal port", input: "example.org:port", wantMessage: "only decimal digits"},
		{name: "empty host", input: ":9200", wantMessage: "host is empty"},
		{name: "missing IPv6 bracket", input: "[2001:db8::1", wantMessage: "closing bracket is missing"},
		{name: "text after IPv6 bracket", input: "[2001:db8::1]extra", wantMessage: "invalid text after IPv6"},
		{name: "bracketed hostname", input: "[example.org]:9200", wantMessage: "brackets are only valid for IPv6"},
		{name: "invalid IPv6 zone", input: "[fe80::1%eth 0]:9200", wantMessage: "IPv6 zone contains unsupported characters"},
		{name: "bare path", input: "example.org/elastic", wantMessage: "path requires an http or https URL"},
		{name: "invalid CIDR", input: "192.0.2.0/99", wantMessage: "invalid CIDR prefix"},
		{name: "numeric invalid IPv4", input: "999.1.1.1", wantMessage: "invalid IPv4 address"},
		{name: "empty hostname label", input: "example..org", wantMessage: "hostname label length"},
		{name: "hostname leading hyphen", input: "-example.org", wantMessage: "start and end with a letter or digit"},
		{name: "hostname underscore", input: "elastic_search.example", wantMessage: "unsupported characters"},
		{name: "non-ASCII hostname", input: "münich.example", wantMessage: "unsupported characters"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, firstErr := target.Parse(test.input, "test")
			if firstErr == nil {
				t.Fatal("Parse() error = nil, want failure")
			}
			if !strings.Contains(firstErr.Error(), test.wantMessage) {
				t.Errorf("Parse() error = %q, want substring %q", firstErr, test.wantMessage)
			}

			_, secondErr := target.Parse(test.input, "test")
			if secondErr == nil || secondErr.Error() != firstErr.Error() {
				t.Errorf("Parse() errors are not deterministic: first = %v, second = %v", firstErr, secondErr)
			}
		})
	}
}

func TestParseCIDRRequiresStreamingExpansion(t *testing.T) {
	_, err := target.Parse("192.168.1.0/24", "test")
	if !errors.Is(err, target.ErrCIDRTarget) {
		t.Fatalf("Parse() error = %v, want ErrCIDRTarget", err)
	}
}

func TestParseCanonicalEquivalence(t *testing.T) {
	tests := []struct {
		name  string
		first string
		other string
	}{
		{name: "hostname case and root dot", first: "Elastic.Example.org.", other: "elastic.example.org"},
		{name: "default HTTP port", first: "http://example.org", other: "http://example.org:80/"},
		{name: "expanded IPv6", first: "2001:0db8:0:0:0:0:0:1", other: "[2001:db8::1]"},
		{name: "percent escape case", first: "https://example.org/%2fstatus", other: "https://example.org/%2Fstatus"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first, err := target.Parse(test.first, "same-source")
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", test.first, err)
			}
			other, err := target.Parse(test.other, "same-source")
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", test.other, err)
			}
			if first != other {
				t.Errorf("equivalent targets differ: first = %#v, other = %#v", first, other)
			}
		})
	}
}

func TestParseDoesNotLeakURLUserInformation(t *testing.T) {
	const secretCanary = "secret-canary"
	_, err := target.Parse("https://audit:"+secretCanary+"@example.org", "test")
	if err == nil {
		t.Fatal("Parse() error = nil, want failure")
	}
	if strings.Contains(err.Error(), secretCanary) {
		t.Errorf("Parse() error leaks URL user information: %q", err)
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"127.0.0.1",
		"example.org:9200",
		"https://example.org:9243/elastic",
		"[2001:db8::1]:9200",
		"https://[fe80::1%25eth0]:9200",
		"http://audit:secret@example.org",
		"\x00\xff",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		parsed, err := target.Parse(input, "fuzz")
		if err != nil {
			if err.Error() == "" {
				t.Fatal("Parse() returned an empty error message")
			}
			return
		}

		canonical := parsed.String()
		reparsed, err := target.Parse(canonical, "fuzz")
		if err != nil {
			t.Fatalf("Parse() rejected canonical target %q: %v", canonical, err)
		}
		if reparsed != parsed {
			t.Fatalf("canonical round trip changed target: first = %#v, second = %#v", parsed, reparsed)
		}
	})
}
