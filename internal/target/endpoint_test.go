package target

import (
	"testing"

	"github.com/cumakurt/garga/internal/model"
)

func TestEndpointFromTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want model.Endpoint
	}{
		{"192.0.2.10", model.Endpoint{Scheme: model.SchemeHTTP, Host: "192.0.2.10", Port: 9200}},
		{"example.org:9200", model.Endpoint{Scheme: model.SchemeHTTP, Host: "example.org", Port: 9200}},
		{"http://example.org", model.Endpoint{Scheme: model.SchemeHTTP, Host: "example.org", Port: 80}},
		{"https://example.org:9243/elastic", model.Endpoint{Scheme: model.SchemeHTTPS, Host: "example.org", Port: 9243, Path: "/elastic"}},
	}
	for _, test := range tests {
		parsed, err := Parse(test.raw, "test")
		if err != nil {
			t.Fatalf("Parse(%q) error = %v", test.raw, err)
		}
		got, err := Endpoint(parsed)
		if err != nil {
			t.Fatalf("Endpoint(%q) error = %v", test.raw, err)
		}
		if got != test.want {
			t.Fatalf("Endpoint(%q) = %#v, want %#v", test.raw, got, test.want)
		}
	}
}
