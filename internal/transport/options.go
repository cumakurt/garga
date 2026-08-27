package transport

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cumakurt/garga/internal/config"
)

const (
	defaultMaxRedirects       = 3
	defaultIdleConnTimeout    = 90 * time.Second
	defaultExpectContinueTime = time.Second
	defaultMaxResponseHeaders = 64 * 1024
	maxRedirects              = 20
	maxUserAgentBytes         = 256
	maxTransportResponseBytes = 128 * 1024 * 1024
	maxTransportHeaderBytes   = 1024 * 1024
)

// Options defines one reusable HTTP transport policy.
type Options struct {
	ConnectTimeout            time.Duration
	TLSHandshakeTimeout       time.Duration
	ResponseHeaderTimeout     time.Duration
	RequestTimeout            time.Duration
	IdleConnTimeout           time.Duration
	ExpectContinueTimeout     time.Duration
	MaxResponseBytes          int64
	MaxResponseHeaderBytes    int64
	MaxRedirects              int
	MaxIdleConnections        int
	MaxIdleConnectionsPerHost int
	ProxyURL                  string
	DisableEnvironmentProxy   bool
	InsecureSkipVerify        bool
	RootCAs                   *x509.CertPool
	UserAgent                 string
}

// OptionsFromConfig derives a complete transport policy from validated application settings.
func OptionsFromConfig(cfg config.Config, userAgent string) (Options, error) {
	if err := cfg.Validate(); err != nil {
		return Options{}, err
	}
	if strings.TrimSpace(userAgent) == "" {
		userAgent = "garga/dev"
	}

	maxIdleConnections := cfg.Scanner.Concurrency * 2
	if maxIdleConnections < 100 {
		maxIdleConnections = 100
	}

	return Options{
		ConnectTimeout:            cfg.Scanner.ConnectTimeout,
		TLSHandshakeTimeout:       cfg.Scanner.ConnectTimeout,
		ResponseHeaderTimeout:     cfg.Scanner.RequestTimeout,
		RequestTimeout:            cfg.Scanner.RequestTimeout,
		IdleConnTimeout:           defaultIdleConnTimeout,
		ExpectContinueTimeout:     defaultExpectContinueTime,
		MaxResponseBytes:          cfg.Scanner.MaxResponseBytes,
		MaxResponseHeaderBytes:    defaultMaxResponseHeaders,
		MaxRedirects:              defaultMaxRedirects,
		MaxIdleConnections:        maxIdleConnections,
		MaxIdleConnectionsPerHost: cfg.Scanner.Concurrency,
		UserAgent:                 userAgent,
	}, nil
}

func (options Options) validate() (*url.URL, error) {
	positiveDurations := []struct {
		name  string
		value time.Duration
	}{
		{"connect timeout", options.ConnectTimeout},
		{"TLS handshake timeout", options.TLSHandshakeTimeout},
		{"response header timeout", options.ResponseHeaderTimeout},
		{"request timeout", options.RequestTimeout},
		{"idle connection timeout", options.IdleConnTimeout},
		{"expect-continue timeout", options.ExpectContinueTimeout},
	}
	for _, setting := range positiveDurations {
		if setting.value <= 0 {
			return nil, fmt.Errorf("invalid transport options: %s must be greater than zero", setting.name)
		}
	}
	if options.MaxResponseBytes < 1 || options.MaxResponseBytes > maxTransportResponseBytes {
		return nil, fmt.Errorf("invalid transport options: maximum response bytes must be between 1 and %d", maxTransportResponseBytes)
	}
	if options.MaxResponseHeaderBytes < 1 || options.MaxResponseHeaderBytes > maxTransportHeaderBytes {
		return nil, fmt.Errorf("invalid transport options: maximum response header bytes must be between 1 and %d", maxTransportHeaderBytes)
	}
	if options.MaxRedirects < 0 || options.MaxRedirects > maxRedirects {
		return nil, fmt.Errorf("invalid transport options: maximum redirects must be between 0 and %d", maxRedirects)
	}
	if options.MaxIdleConnections < 1 {
		return nil, fmt.Errorf("invalid transport options: maximum idle connections must be greater than zero")
	}
	if options.MaxIdleConnectionsPerHost < 1 || options.MaxIdleConnectionsPerHost > options.MaxIdleConnections {
		return nil, fmt.Errorf("invalid transport options: per-host idle connections must be between 1 and the global idle connection limit")
	}
	if !validUserAgent(options.UserAgent) {
		return nil, fmt.Errorf("invalid transport options: user agent must be valid UTF-8 without control characters and at most %d bytes", maxUserAgentBytes)
	}

	if strings.TrimSpace(options.ProxyURL) == "" {
		return nil, nil
	}
	proxyURL, err := url.Parse(options.ProxyURL)
	if err != nil || proxyURL.Host == "" {
		return nil, fmt.Errorf("invalid transport options: proxy URL is invalid")
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("invalid transport options: proxy URL scheme must be http, https, socks5, or socks5h")
	}
	return proxyURL, nil
}

func validUserAgent(value string) bool {
	if value == "" || len(value) > maxUserAgentBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
