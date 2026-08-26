package transport

import (
	"strings"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/config"
)

func TestOptionsFromConfig(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	options, err := OptionsFromConfig(cfg, "garga/test")
	if err != nil {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
	if options.ConnectTimeout != cfg.Scanner.ConnectTimeout ||
		options.RequestTimeout != cfg.Scanner.RequestTimeout ||
		options.MaxResponseBytes != cfg.Scanner.MaxResponseBytes {
		t.Fatalf("OptionsFromConfig() did not copy scanner limits: %#v", options)
	}
	if options.UserAgent != "garga/test" {
		t.Fatalf("user agent = %q, want garga/test", options.UserAgent)
	}
	if options.MaxIdleConnectionsPerHost != cfg.Scanner.Concurrency {
		t.Fatalf("per-host idle limit = %d, want %d", options.MaxIdleConnectionsPerHost, cfg.Scanner.Concurrency)
	}
	if options.MaxIdleConnections < options.MaxIdleConnectionsPerHost {
		t.Fatalf("global idle limit %d is below per-host limit %d", options.MaxIdleConnections, options.MaxIdleConnectionsPerHost)
	}
}

func TestOptionsFromConfigRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Scanner.Concurrency = 0
	_, err := OptionsFromConfig(cfg, "garga/test")
	if err == nil || !strings.Contains(err.Error(), "scanner.concurrency") {
		t.Fatalf("OptionsFromConfig() error = %v, want configuration validation error", err)
	}
}

func TestOptionsValidateRejectsInvalidValuesWithoutEchoingInput(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"connect timeout", func(options *Options) { options.ConnectTimeout = 0 }},
		{"TLS timeout", func(options *Options) { options.TLSHandshakeTimeout = 0 }},
		{"response timeout", func(options *Options) { options.ResponseHeaderTimeout = 0 }},
		{"request timeout", func(options *Options) { options.RequestTimeout = 0 }},
		{"idle timeout", func(options *Options) { options.IdleConnTimeout = 0 }},
		{"expect timeout", func(options *Options) { options.ExpectContinueTimeout = 0 }},
		{"response limit", func(options *Options) { options.MaxResponseBytes = 0 }},
		{"header limit", func(options *Options) { options.MaxResponseHeaderBytes = 0 }},
		{"redirect limit", func(options *Options) { options.MaxRedirects = -1 }},
		{"global idle limit", func(options *Options) { options.MaxIdleConnections = 0 }},
		{"host idle limit", func(options *Options) { options.MaxIdleConnectionsPerHost = 101 }},
		{"user agent", func(options *Options) { options.UserAgent = canary + "\n" }},
		{"proxy URL", func(options *Options) { options.ProxyURL = "://" + canary }},
		{"proxy scheme", func(options *Options) { options.ProxyURL = "file://" + canary }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := testOptions(t)
			test.mutate(&options)
			_, err := options.validate()
			if err == nil {
				t.Fatal("validate() returned nil")
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatalf("validate() error exposed canary: %q", err)
			}
		})
	}
}

func TestDefaultUserAgent(t *testing.T) {
	t.Parallel()

	options, err := OptionsFromConfig(config.Defaults(), " ")
	if err != nil {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
	if options.UserAgent != "garga/dev" {
		t.Fatalf("user agent = %q, want garga/dev", options.UserAgent)
	}
}

func testOptions(t *testing.T) Options {
	t.Helper()
	options, err := OptionsFromConfig(config.Defaults(), "garga/test")
	if err != nil {
		t.Fatalf("OptionsFromConfig(): %v", err)
	}
	options.DisableEnvironmentProxy = true
	options.ConnectTimeout = 500 * time.Millisecond
	options.TLSHandshakeTimeout = 500 * time.Millisecond
	options.ResponseHeaderTimeout = 500 * time.Millisecond
	options.RequestTimeout = time.Second
	return options
}
