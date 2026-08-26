package model

import (
	"strings"
	"testing"
)

func TestEndpointURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint Endpoint
		want     string
	}{
		{"HTTP hostname", Endpoint{Scheme: SchemeHTTP, Host: "example.com", Port: 9200}, "http://example.com:9200/"},
		{"HTTPS path", Endpoint{Scheme: SchemeHTTPS, Host: "example.com", Port: 443, Path: "/prefix/%7Eroot"}, "https://example.com:443/prefix/%7Eroot"},
		{"IPv6", Endpoint{Scheme: SchemeHTTP, Host: "2001:db8::1", Port: 9200}, "http://[2001:db8::1]:9200/"},
		{"IPv6 zone", Endpoint{Scheme: SchemeHTTP, Host: "fe80::1%eth0", Port: 9200}, "http://[fe80::1%25eth0]:9200/"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := test.endpoint.URL()
			if err != nil {
				t.Fatalf("URL() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("URL() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestEndpointURLRejectsInvalidComponentsWithoutEchoingThem(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	tests := []Endpoint{
		{Scheme: SchemeAuto, Host: "example.com", Port: 9200},
		{Scheme: SchemeHTTP, Host: "", Port: 9200},
		{Scheme: SchemeHTTP, Host: "example.com/" + canary, Port: 9200},
		{Scheme: SchemeHTTP, Host: "example.com", Port: 0},
		{Scheme: SchemeHTTP, Host: "example.com", Port: 65536},
		{Scheme: SchemeHTTP, Host: "example.com", Port: 9200, Path: canary},
		{Scheme: SchemeHTTP, Host: "example.com", Port: 9200, Path: "/?token=" + canary},
		{Scheme: SchemeHTTP, Host: "example.com", Port: 9200, Path: "/%zz" + canary},
	}

	for _, endpoint := range tests {
		_, err := endpoint.URL()
		if err == nil {
			t.Fatalf("URL() returned nil error for %#v", endpoint)
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatalf("URL() error exposed canary: %q", err)
		}
	}
}
