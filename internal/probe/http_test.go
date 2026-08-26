package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/transport"
)

func TestHTTPProberRetainsOnlyFingerprintData(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", request.Method)
		}
		if request.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q, want application/json", request.Header.Get("Accept"))
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Add("Server", "z-server")
		writer.Header().Add("Server", "a-server")
		writer.Header().Set("Www-Authenticate", `Basic realm="cluster"`)
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		writer.Header().Set("Set-Cookie", "session="+canary)
		writer.Header().Set("X-Secret", canary)
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, `{"error":"authentication required"}`)
	}))
	defer server.Close()

	endpoint := endpointForServer(t, server.URL)
	endpoint.Path = "/" + canary
	result, err := newTestProber(t, 4096).Probe(context.Background(), endpoint)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if result.Request.Method != http.MethodGet || result.Request.Resource != ResourceCustomPath {
		t.Fatalf("request metadata = %#v", result.Request)
	}
	if result.StatusCode != http.StatusUnauthorized || result.Protocol == "" {
		t.Fatalf("response metadata = %#v", result)
	}
	if got := string(result.Body); got != `{"error":"authentication required"}` {
		t.Fatalf("body = %q", got)
	}
	if got := fmt.Sprintf("%+v", result); strings.Contains(got, canary) {
		t.Fatalf("result retained request path or excluded headers: %s", got)
	}

	wantHeaders := []HeaderField{
		{Name: "Content-Type", Values: []string{"application/json"}},
		{Name: "Server", Values: []string{"a-server", "z-server"}},
		{Name: "Www-Authenticate", Values: []string{`Basic realm="cluster"`}},
		{Name: "X-Elastic-Product", Values: []string{"Elasticsearch"}},
	}
	if !reflect.DeepEqual(result.Headers, wantHeaders) {
		t.Fatalf("headers = %#v, want %#v", result.Headers, wantHeaders)
	}
}

func TestHTTPProberRootMetadata(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	}))
	defer server.Close()

	result, err := newTestProber(t, 1024).Probe(context.Background(), endpointForServer(t, server.URL))
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if result.Request.Resource != ResourceRoot {
		t.Fatalf("resource = %q, want %q", result.Request.Resource, ResourceRoot)
	}
}

func TestRetainHeadersIsBoundedSanitizedAndDeterministic(t *testing.T) {
	t.Parallel()

	values := []string{"z-value", "a-value", "a-value", "tabs\tand\x00controls"}
	for index := 0; index < 10; index++ {
		values = append(values, fmt.Sprintf("value-%02d", index))
	}
	headers := http.Header{
		"Server":            values,
		"Warning":           {strings.Repeat("é", 700)},
		"X-Elastic-Product": {string([]byte{'E', 'S', 0xff})},
		"Set-Cookie":        {"credential-canary"},
	}

	first := retainHeaders(headers)
	second := retainHeaders(headers.Clone())
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("retainHeaders() is not deterministic:\n%#v\n%#v", first, second)
	}
	for _, field := range first {
		if len(field.Values) > maxRetainedHeaderValues {
			t.Fatalf("%s retained %d values", field.Name, len(field.Values))
		}
		totalBytes := 0
		for _, value := range field.Values {
			totalBytes += len(value)
			if !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n\t") {
				t.Fatalf("%s retained an unsafe value %q", field.Name, value)
			}
		}
		if totalBytes > maxRetainedHeaderBytes {
			t.Fatalf("%s retained %d bytes, limit %d", field.Name, totalBytes, maxRetainedHeaderBytes)
		}
		if field.Name == "Server" || field.Name == "Warning" {
			if !field.Truncated {
				t.Fatalf("%s was not marked truncated", field.Name)
			}
		}
	}
	if got := fmt.Sprintf("%+v", first); strings.Contains(got, "credential-canary") {
		t.Fatalf("retainHeaders() retained a non-allowlisted header: %s", got)
	}
}

func TestHTTPProberResultsAreDeterministic(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Add("Server", "second")
		writer.Header().Add("Server", "first")
		writer.Header().Set("X-Elastic-Product", "Elasticsearch")
		_, _ = io.WriteString(writer, `{"version":{"number":"8.17.0"}}`)
	}))
	defer server.Close()

	prober := newTestProber(t, 4096)
	endpoint := endpointForServer(t, server.URL)
	first, err := prober.Probe(context.Background(), endpoint)
	if err != nil {
		t.Fatalf("first Probe() error = %v", err)
	}
	second, err := prober.Probe(context.Background(), endpoint)
	if err != nil {
		t.Fatalf("second Probe() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("equivalent responses produced different results:\n%#v\n%#v", first, second)
	}
}

func TestHTTPProberErrorTaxonomy(t *testing.T) {
	t.Parallel()

	t.Run("invalid endpoint", func(t *testing.T) {
		t.Parallel()
		_, err := newTestProber(t, 1024).Probe(context.Background(), model.Endpoint{Host: "credential-canary"})
		assertProbeError(t, err, ErrorInvalidEndpoint)
	})

	t.Run("canceled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		endpoint := model.Endpoint{Scheme: model.SchemeHTTP, Host: "127.0.0.1", Port: 1}
		_, err := newTestProber(t, 1024).Probe(ctx, endpoint)
		assertProbeError(t, err, ErrorCanceled)
	})

	t.Run("TCP", func(t *testing.T) {
		t.Parallel()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen() error = %v", err)
		}
		address := listener.Addr().(*net.TCPAddr)
		if err := listener.Close(); err != nil {
			t.Fatalf("listener.Close() error = %v", err)
		}
		endpoint := model.Endpoint{Scheme: model.SchemeHTTP, Host: "127.0.0.1", Port: address.Port}
		_, err = newTestProber(t, 1024).Probe(context.Background(), endpoint)
		assertProbeError(t, err, ErrorTCP)
	})

	t.Run("TLS", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		defer server.Close()
		_, err := newTestProber(t, 1024).Probe(context.Background(), endpointForServer(t, server.URL))
		assertProbeError(t, err, ErrorTLS)
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			<-request.Context().Done()
		}))
		defer server.Close()
		prober := newTestProberWithTimeout(t, 1024, 50*time.Millisecond)
		_, err := prober.Probe(context.Background(), endpointForServer(t, server.URL))
		assertProbeError(t, err, ErrorTimeout)
	})

	t.Run("HTTP response limit", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(writer, "too large")
		}))
		defer server.Close()
		_, err := newTestProber(t, 4).Probe(context.Background(), endpointForServer(t, server.URL))
		assertProbeError(t, err, ErrorHTTP)
	})
}

func TestHTTPProberErrorDoesNotExposeRequestMetadata(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil || line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(connection, "malformed-response\r\n\r\n")
	}()
	defer listener.Close()

	address := listener.Addr().(*net.TCPAddr)
	endpoint := model.Endpoint{
		Scheme: model.SchemeHTTP,
		Host:   "127.0.0.1",
		Port:   address.Port,
		Path:   "/" + canary,
	}
	_, err = newTestProber(t, 1024).Probe(context.Background(), endpoint)
	assertProbeError(t, err, ErrorHTTP)
	if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), endpoint.Host) {
		t.Fatalf("Probe() error exposed request metadata: %q", err)
	}
	if cause := errors.Unwrap(err); cause == nil || strings.Contains(cause.Error(), canary) {
		t.Fatalf("Probe() cause is missing or exposed metadata: %v", cause)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("malformed-response server did not stop")
	}
}

func TestNewHTTPRejectsNilClient(t *testing.T) {
	t.Parallel()

	if _, err := NewHTTP(nil); err == nil {
		t.Fatal("NewHTTP(nil) returned nil error")
	}
	var prober *HTTPProber
	_, err := prober.Probe(context.Background(), model.Endpoint{})
	assertProbeError(t, err, ErrorInvalidEndpoint)
}

func TestKindOfRejectsNonProbeError(t *testing.T) {
	t.Parallel()

	if _, ok := KindOf(errors.New("other")); ok {
		t.Fatal("KindOf() classified a non-probe error")
	}
}

func newTestProber(t *testing.T, maxResponseBytes int64) *HTTPProber {
	t.Helper()
	return newTestProberWithTimeout(t, maxResponseBytes, time.Second)
}

func newTestProberWithTimeout(t *testing.T, maxResponseBytes int64, timeout time.Duration) *HTTPProber {
	t.Helper()
	options, err := transport.OptionsFromConfig(config.Defaults(), "garga/probe-test")
	if err != nil {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
	options.DisableEnvironmentProxy = true
	options.MaxResponseBytes = maxResponseBytes
	options.RequestTimeout = timeout
	options.ResponseHeaderTimeout = timeout
	factory, err := transport.NewFactory(options)
	if err != nil {
		t.Fatalf("NewFactory() error = %v", err)
	}
	t.Cleanup(factory.CloseIdleConnections)
	prober, err := NewHTTP(factory.Client())
	if err != nil {
		t.Fatalf("NewHTTP() error = %v", err)
	}
	return prober
}

func endpointForServer(t *testing.T, rawURL string) model.Endpoint {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	address := request.URL.Hostname()
	port := request.URL.Port()
	var portNumber int
	if _, err := fmt.Sscanf(port, "%d", &portNumber); err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	scheme := model.SchemeHTTP
	if request.URL.Scheme == "https" {
		scheme = model.SchemeHTTPS
	}
	return model.Endpoint{Scheme: scheme, Host: address, Port: portNumber}
}

func assertProbeError(t *testing.T, err error, want ErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %q", want)
	}
	got, ok := KindOf(err)
	if !ok || got != want {
		t.Fatalf("KindOf(%v) = %q, %t; want %q, true", err, got, ok, want)
	}
}
