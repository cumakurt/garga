package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Response is a fully consumed, bounded HTTP response.
type Response struct {
	StatusCode int
	Status     string
	Protocol   string
	Header     http.Header
	Body       []byte
}

// Client applies one immutable transport policy across many requests.
type Client struct {
	httpClient       *http.Client
	transport        *http.Transport
	maxResponseBytes int64
	userAgent        string
}

// Factory owns one reusable client and connection pool for a compatible policy.
type Factory struct {
	client *Client
}

// NewFactory validates options and constructs one shared transport/client pair.
func NewFactory(options Options) (*Factory, error) {
	proxyURL, err := options.validate()
	if err != nil {
		return nil, err
	}

	proxy := http.ProxyFromEnvironment
	if options.DisableEnvironmentProxy {
		proxy = nil
	}
	if proxyURL != nil {
		proxy = http.ProxyURL(proxyURL)
	}
	rootCAs := options.RootCAs
	if rootCAs != nil {
		rootCAs = rootCAs.Clone()
	}

	httpTransport := &http.Transport{
		Proxy: proxy,
		DialContext: (&net.Dialer{
			Timeout:   options.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           options.MaxIdleConnections,
		MaxIdleConnsPerHost:    options.MaxIdleConnectionsPerHost,
		IdleConnTimeout:        options.IdleConnTimeout,
		TLSHandshakeTimeout:    options.TLSHandshakeTimeout,
		ResponseHeaderTimeout:  options.ResponseHeaderTimeout,
		ExpectContinueTimeout:  options.ExpectContinueTimeout,
		MaxResponseHeaderBytes: options.MaxResponseHeaderBytes,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			RootCAs:            rootCAs,
			InsecureSkipVerify: options.InsecureSkipVerify,
		},
	}

	redirects := options.MaxRedirects
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   options.RequestTimeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) > redirects {
				return errRedirectLimit
			}
			if request.URL.User != nil {
				return errInvalidRequest
			}
			if len(via) > 0 && !sameOrigin(via[len(via)-1].URL, request.URL) {
				request.Header.Del("Authorization")
				request.Header.Del("Proxy-Authorization")
				request.Header.Del("Cookie")
				request.Header.Del("Referer")
			}
			return nil
		},
	}

	return &Factory{client: &Client{
		httpClient:       httpClient,
		transport:        httpTransport,
		maxResponseBytes: options.MaxResponseBytes,
		userAgent:        options.UserAgent,
	}}, nil
}

// Client returns the factory's shared client. It is safe for concurrent use.
func (factory *Factory) Client() *Client {
	return factory.client
}

// CloseIdleConnections releases pooled idle connections owned by the factory.
func (factory *Factory) CloseIdleConnections() {
	if factory == nil || factory.client == nil {
		return
	}
	factory.client.CloseIdleConnections()
}

// Do sends a request, consumes and closes its body, and returns a bounded response.
func (client *Client) Do(request *http.Request) (Response, error) {
	if client == nil || client.httpClient == nil || !validRequest(request) {
		return Response{}, &Error{kind: ErrorInvalidRequest, operation: "request", cause: errInvalidRequest}
	}

	clonedRequest := request.Clone(request.Context())
	if clonedRequest.Header == nil {
		clonedRequest.Header = make(http.Header)
	}
	clonedRequest.Header.Set("User-Agent", client.userAgent)

	httpResponse, err := client.httpClient.Do(clonedRequest)
	if err != nil {
		if httpResponse != nil && httpResponse.Body != nil {
			_ = httpResponse.Body.Close()
		}
		return Response{}, classifyRequestError(err)
	}

	body, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, client.maxResponseBytes+1))
	closeErr := httpResponse.Body.Close()
	if readErr != nil {
		return Response{}, &Error{kind: ErrorRead, operation: "response", cause: readErr}
	}
	if int64(len(body)) > client.maxResponseBytes {
		return Response{}, &Error{kind: ErrorResponseTooLarge, operation: "response", cause: errResponseTooLarge}
	}
	if closeErr != nil {
		return Response{}, &Error{kind: ErrorRead, operation: "response", cause: closeErr}
	}

	return Response{
		StatusCode: httpResponse.StatusCode,
		Status:     httpResponse.Status,
		Protocol:   httpResponse.Proto,
		Header:     httpResponse.Header.Clone(),
		Body:       body,
	}, nil
}

func validRequest(request *http.Request) bool {
	if request == nil || request.URL == nil || request.URL.Host == "" || request.URL.User != nil {
		return false
	}
	switch strings.ToLower(request.URL.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

// NewRequest constructs a request while preventing raw URL parser errors from escaping.
func NewRequest(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" || parsedURL.User != nil {
		return nil, &Error{kind: ErrorInvalidRequest, operation: "request", cause: errInvalidRequest}
	}
	request, err := http.NewRequestWithContext(ctx, method, parsedURL.String(), body)
	if err != nil {
		return nil, &Error{kind: ErrorInvalidRequest, operation: "request", cause: errInvalidRequest}
	}
	return request, nil
}

// CloseIdleConnections releases this client's pooled idle connections.
func (client *Client) CloseIdleConnections() {
	if client == nil || client.transport == nil {
		return
	}
	client.transport.CloseIdleConnections()
}
