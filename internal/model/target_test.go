package model_test

import (
	"testing"

	"github.com/cumakurt/garga/internal/model"
)

func TestTargetString(t *testing.T) {
	tests := []struct {
		name   string
		target model.Target
		want   string
	}{
		{
			name:   "hostname without port",
			target: model.Target{Host: "example.org"},
			want:   "example.org",
		},
		{
			name:   "hostname with port",
			target: model.Target{Host: "example.org", Port: 9200},
			want:   "example.org:9200",
		},
		{
			name:   "IPv6 without port",
			target: model.Target{Host: "2001:db8::1"},
			want:   "[2001:db8::1]",
		},
		{
			name:   "IPv6 zone with port",
			target: model.Target{Host: "fe80::1%eth0", Port: 9200},
			want:   "[fe80::1%eth0]:9200",
		},
		{
			name: "HTTP URL",
			target: model.Target{
				Host:       "example.org",
				Port:       80,
				SchemeHint: model.SchemeHTTP,
			},
			want: "http://example.org:80",
		},
		{
			name: "HTTPS IPv6 zone URL",
			target: model.Target{
				Host:       "fe80::1%eth0",
				Port:       9243,
				SchemeHint: model.SchemeHTTPS,
				Path:       "/elastic",
			},
			want: "https://[fe80::1%25eth0]:9243/elastic",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.target.String(); got != test.want {
				t.Errorf("Target.String() = %q, want %q", got, test.want)
			}
		})
	}
}
