package transport

import (
	"bufio"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientSuccessAndUserAgent(t *testing.T) {
	t.Parallel()

	userAgents := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		userAgents <- request.Header.Get("User-Agent")
		writer.Header().Set("X-Test", "value")
		writer.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(writer, "response")
	}))
	defer server.Close()

	factory := newTestFactory(t, testOptions(t))
	request := mustRequest(t, context.Background(), http.MethodGet, server.URL)
	response, err := factory.Client().Do(request)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if response.StatusCode != http.StatusCreated || response.Status != "201 Created" || response.Protocol == "" {
		t.Fatalf("unexpected response metadata: %#v", response)
	}
	if got := string(response.Body); got != "response" {
		t.Fatalf("body = %q, want response", got)
	}
	if got := response.Header.Get("X-Test"); got != "value" {
		t.Fatalf("X-Test = %q, want value", got)
	}
	if got := <-userAgents; got != "garga/test" {
		t.Fatalf("User-Agent = %q, want garga/test", got)
	}
	if request.Header.Get("User-Agent") != "" {
		t.Fatal("Do() mutated the caller's request")
	}
}

func TestFactoryReturnsOneSharedClientAndReusesConnection(t *testing.T) {
	t.Parallel()

	var newConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	factory := newTestFactory(t, testOptions(t))
	firstClient := factory.Client()
	if factory.Client() != firstClient {
		t.Fatal("factory returned different client instances")
	}
	for range 2 {
		request := mustRequest(t, context.Background(), http.MethodGet, server.URL)
		if _, err := factory.Client().Do(request); err != nil {
			t.Fatalf("Do() error = %v", err)
		}
	}
	if got := newConnections.Load(); got != 1 {
		t.Fatalf("new connections = %d, want 1", got)
	}
	factory.CloseIdleConnections()
}

func TestClientTLSVerificationPolicy(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "secure")
	}))
	defer server.Close()

	t.Run("untrusted certificate", func(t *testing.T) {
		options := testOptions(t)
		factory := newTestFactory(t, options)
		_, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, server.URL))
		assertErrorKind(t, err, ErrorTLS)
	})

	t.Run("custom trust root", func(t *testing.T) {
		options := testOptions(t)
		options.RootCAs = x509.NewCertPool()
		options.RootCAs.AddCert(server.Certificate())
		factory := newTestFactory(t, options)
		if _, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, server.URL)); err != nil {
			t.Fatalf("Do() error = %v", err)
		}
	})

	t.Run("explicit insecure mode", func(t *testing.T) {
		options := testOptions(t)
		options.InsecureSkipVerify = true
		factory := newTestFactory(t, options)
		if _, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, server.URL)); err != nil {
			t.Fatalf("Do() error = %v", err)
		}
	})
}

func TestClientRequestTimeout(t *testing.T) {
	t.Parallel()

	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		<-request.Context().Done()
	}))
	defer server.Close()

	options := testOptions(t)
	options.RequestTimeout = 50 * time.Millisecond
	options.ResponseHeaderTimeout = time.Second
	factory := newTestFactory(t, options)
	_, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, server.URL))
	assertErrorKind(t, err, ErrorTimeout)
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("request did not reach server")
	}
}

func TestClientResponseHeaderTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer server.Close()

	options := testOptions(t)
	options.ResponseHeaderTimeout = 50 * time.Millisecond
	options.RequestTimeout = time.Second
	factory := newTestFactory(t, options)
	_, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, server.URL))
	assertErrorKind(t, err, ErrorTimeout)
}

func TestClientTLSHandshakeTimeout(t *testing.T) {
	t.Parallel()

	address, wait := startRawServer(t, func(connection net.Conn) {
		_, _ = io.Copy(io.Discard, connection)
	})
	options := testOptions(t)
	options.TLSHandshakeTimeout = 50 * time.Millisecond
	options.RequestTimeout = time.Second
	factory := newTestFactory(t, options)
	_, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, "https://"+address))
	assertErrorKind(t, err, ErrorTimeout)
	wait()
}

func TestClientRedirectLimit(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		http.Redirect(writer, request, "/again", http.StatusFound)
	}))
	defer server.Close()

	options := testOptions(t)
	options.MaxRedirects = 2
	factory := newTestFactory(t, options)
	_, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, server.URL))
	assertErrorKind(t, err, ErrorRedirect)
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests = %d, want initial request plus two redirects", got)
	}
}

func TestClientStripsSensitiveHeadersOnCrossOriginRedirect(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	receivedHeaders := make(chan http.Header, 1)
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		receivedHeaders <- request.Header.Clone()
		_, _ = io.WriteString(writer, "ok")
	}))
	defer destination.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusFound)
	}))
	defer origin.Close()

	factory := newTestFactory(t, testOptions(t))
	request := mustRequest(t, context.Background(), http.MethodGet, origin.URL)
	request.Header.Set("Authorization", "Bearer "+canary)
	request.Header.Set("Proxy-Authorization", "Basic "+canary)
	request.Header.Set("Cookie", "session="+canary)
	request.Header.Set("Referer", "https://example.invalid/?token="+canary)
	if _, err := factory.Client().Do(request); err != nil {
		t.Fatalf("Do() error = %v", err)
	}

	headers := <-receivedHeaders
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Referer"} {
		if value := headers.Get(name); value != "" {
			t.Fatalf("destination received %s: %q", name, value)
		}
	}
}

func TestClientResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, strings.Repeat("x", 9))
	}))
	defer server.Close()

	options := testOptions(t)
	options.MaxResponseBytes = 8
	factory := newTestFactory(t, options)
	_, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, server.URL))
	assertErrorKind(t, err, ErrorResponseTooLarge)
}

func TestClientResponseHeaderLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Large", strings.Repeat("x", 1024))
		_, _ = io.WriteString(writer, "ok")
	}))
	defer server.Close()

	options := testOptions(t)
	options.MaxResponseHeaderBytes = 128
	factory := newTestFactory(t, options)
	_, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, server.URL))
	assertErrorKind(t, err, ErrorProtocol)
}

func TestClientMalformedResponseIsSanitized(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	address, wait := startRawServer(t, func(connection net.Conn) {
		readRequestHeaders(connection)
		_, _ = io.WriteString(connection, canary+"\r\n\r\n")
	})

	factory := newTestFactory(t, testOptions(t))
	_, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, "http://"+address))
	assertErrorKind(t, err, ErrorProtocol)
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("Do() error exposed response content: %q", err)
	}
	wait()
}

func TestClientTruncatedResponse(t *testing.T) {
	t.Parallel()

	address, wait := startRawServer(t, func(connection net.Conn) {
		readRequestHeaders(connection)
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort")
	})

	factory := newTestFactory(t, testOptions(t))
	_, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, "http://"+address))
	assertErrorKind(t, err, ErrorRead)
	wait()
}

func TestClientExplicitProxy(t *testing.T) {
	t.Parallel()

	requests := make(chan *http.Request, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests <- request.Clone(context.Background())
		_, _ = io.WriteString(writer, "proxied")
	}))
	defer proxy.Close()

	options := testOptions(t)
	options.ProxyURL = proxy.URL
	factory := newTestFactory(t, options)
	response, err := factory.Client().Do(mustRequest(t, context.Background(), http.MethodGet, "http://example.invalid/resource"))
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if string(response.Body) != "proxied" {
		t.Fatalf("body = %q, want proxied", response.Body)
	}
	received := <-requests
	if received.URL.Host != "example.invalid" || received.URL.Path != "/resource" {
		t.Fatalf("proxy received URL %q", received.URL)
	}
}

func TestClientCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	factory := newTestFactory(t, testOptions(t))
	_, err := factory.Client().Do(mustRequest(t, ctx, http.MethodGet, "http://127.0.0.1:1"))
	assertErrorKind(t, err, ErrorCanceled)
}

func TestClientRejectsNonGETAndRequestBodies(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()

	factory := newTestFactory(t, testOptions(t))
	ctx := context.Background()
	methods := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodHead,
		http.MethodOptions,
		"get",
		"",
	}
	for _, method := range methods {
		_, err := NewRequest(ctx, method, server.URL, nil)
		assertErrorKind(t, err, ErrorInvalidRequest)
		if strings.Contains(err.Error(), server.URL) {
			t.Fatalf("NewRequest(%q) error exposed URL: %q", method, err)
		}

		request, err := http.NewRequestWithContext(ctx, method, server.URL, nil)
		if err != nil {
			t.Fatalf("http.NewRequestWithContext(%q) error = %v", method, err)
		}
		request.Method = method
		_, err = factory.Client().Do(request)
		assertErrorKind(t, err, ErrorInvalidRequest)
	}

	_, err := NewRequest(ctx, http.MethodGet, server.URL, strings.NewReader("{}"))
	assertErrorKind(t, err, ErrorInvalidRequest)

	bodyRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}
	_, err = factory.Client().Do(bodyRequest)
	assertErrorKind(t, err, ErrorInvalidRequest)

	if got := hits.Load(); got != 0 {
		t.Fatalf("server received %d rejected requests", got)
	}
}

func TestClientRejectsUnsafeRequestURLWithoutExposingCredentials(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	request, err := http.NewRequest(http.MethodGet, "http://user:"+canary+"@example.invalid/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	factory := newTestFactory(t, testOptions(t))
	_, err = factory.Client().Do(request)
	assertErrorKind(t, err, ErrorInvalidRequest)
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("Do() error exposed credentials: %q", err)
	}

	_, err = NewRequest(context.Background(), http.MethodGet, "http://user:"+canary+"@example.invalid/", nil)
	assertErrorKind(t, err, ErrorInvalidRequest)
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("NewRequest() error exposed credentials: %q", err)
	}
}

func newTestFactory(t *testing.T, options Options) *Factory {
	t.Helper()
	factory, err := NewFactory(options)
	if err != nil {
		t.Fatalf("NewFactory() error = %v", err)
	}
	t.Cleanup(factory.CloseIdleConnections)
	return factory
}

func mustRequest(t *testing.T, ctx context.Context, method, rawURL string) *http.Request {
	t.Helper()
	request, err := NewRequest(ctx, method, rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	return request
}

func assertErrorKind(t *testing.T, err error, want ErrorKind) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want kind %q", want)
	}
	got, ok := KindOf(err)
	if !ok || got != want {
		t.Fatalf("KindOf(%v) = %q, %t; want %q, true", err, got, ok, want)
	}
}

func startRawServer(t *testing.T, serve func(net.Conn)) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		serve(connection)
		done <- nil
	}()
	wait := func() {
		t.Helper()
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("raw server error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("raw server did not stop")
		}
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String(), wait
}

func readRequestHeaders(connection net.Conn) {
	reader := bufio.NewReader(connection)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			return
		}
	}
}
