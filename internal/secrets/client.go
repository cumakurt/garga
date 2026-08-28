package secrets

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/ratelimit"
	"github.com/cumakurt/garga/internal/transport"
)

const (
	maxClientResponseBytes = 16 << 20
	maxSearchBodyBytes     = 64 << 10
)

type esClient struct {
	http      *http.Client
	endpoint  model.Endpoint
	secret    *credential.Secret
	limiter   *ratelimit.Limiter
	retries   int
	userAgent string

	mu       sync.Mutex
	requests int
	failed   int
	slowdown time.Duration
}

type esResponse struct {
	StatusCode int
	Body       []byte
}

type esHTTPError struct {
	method     string
	path       string
	statusCode int
}

func (err *esHTTPError) Error() string {
	return fmt.Sprintf("%s %s returned HTTP %d %s", err.method, err.path, err.statusCode, http.StatusText(err.statusCode))
}

type esDecodeError struct {
	path string
	err  error
}

func (err *esDecodeError) Error() string { return fmt.Sprintf("decode %s: %v", err.path, err.err) }
func (err *esDecodeError) Unwrap() error { return err.err }

func responseWasReceived(err error) bool {
	var statusErr *esHTTPError
	var decodeErr *esDecodeError
	return errors.As(err, &statusErr) || errors.As(err, &decodeErr)
}

func newESClient(endpoint model.Endpoint, secret *credential.Secret, options Options, userAgent string) (*esClient, error) {
	if _, err := endpoint.URL(); err != nil {
		return nil, fmt.Errorf("secrets target: %w", err)
	}
	if secret != nil && endpoint.Scheme != model.SchemeHTTPS && !options.AllowPlaintextAuth {
		return nil, fmt.Errorf("refusing to send credentials over HTTP; use https or --allow-plaintext-auth")
	}
	tlsConfig, err := tlsConfig(options)
	if err != nil {
		return nil, err
	}
	limiter, err := ratelimit.New(options.RateLimit, options.RateLimit)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(userAgent) == "" {
		userAgent = "garga/dev"
	}
	transportHTTP := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: options.RequestTimeout,
		TLSClientConfig:       tlsConfig,
	}
	return &esClient{
		http: &http.Client{
			Transport: transportHTTP,
			Timeout:   options.RequestTimeout,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("too many redirects")
				}
				if request.URL.User != nil {
					return errors.New("redirect with userinfo is not allowed")
				}
				if !allowlistedRequest(request.Method, request.URL.Path) {
					return errors.New("redirect method or path is not allowlisted")
				}
				if len(via) > 0 && (via[len(via)-1].URL.Scheme != request.URL.Scheme || via[len(via)-1].URL.Host != request.URL.Host) {
					stripRedirectCredentials(request)
				}
				return nil
			},
		},
		endpoint:  endpoint,
		secret:    secret,
		limiter:   limiter,
		retries:   options.Retries,
		userAgent: userAgent,
	}, nil
}

func tlsConfig(options Options) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.Insecure}
	if caPath := strings.TrimSpace(options.CACert); caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA certificate is invalid")
		}
		config.RootCAs = pool
	}
	certPath := strings.TrimSpace(options.ClientCert)
	keyPath := strings.TrimSpace(options.ClientKey)
	if certPath != "" && keyPath != "" {
		certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

func (client *esClient) getJSON(ctx context.Context, path string, query url.Values, dest any) error {
	response, err := client.do(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return &esHTTPError{method: http.MethodGet, path: path, statusCode: response.StatusCode}
	}
	if dest == nil {
		return nil
	}
	if err := json.Unmarshal(response.Body, dest); err != nil {
		return &esDecodeError{path: path, err: err}
	}
	return nil
}

func (client *esClient) postSearch(ctx context.Context, index string, body []byte, dest any) error {
	if !validIndexName(index) {
		return fmt.Errorf("index name is invalid")
	}
	if int64(len(body)) > maxSearchBodyBytes {
		return fmt.Errorf("search body exceeds %d bytes", maxSearchBodyBytes)
	}
	path := "/" + url.PathEscape(index) + "/_search"
	response, err := client.do(ctx, http.MethodPost, path, nil, body)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return &esHTTPError{method: http.MethodPost, path: path, statusCode: response.StatusCode}
	}
	if err := json.Unmarshal(response.Body, dest); err != nil {
		return fmt.Errorf("decode search response: %w", err)
	}
	return nil
}

func (client *esClient) do(ctx context.Context, method, path string, query url.Values, body []byte) (esResponse, error) {
	if !allowlistedRequest(method, path) {
		return esResponse{}, fmt.Errorf("elasticsearch request is not allowlisted")
	}
	rawURL, err := client.requestURL(path, query)
	if err != nil {
		return esResponse{}, err
	}
	for attempt := 0; ; attempt++ {
		if err := client.limiter.Wait(ctx, client.endpoint.Host); err != nil {
			return esResponse{}, err
		}
		if err := client.waitSlowdown(ctx); err != nil {
			return esResponse{}, err
		}
		var reader io.Reader
		if len(body) > 0 {
			reader = bytes.NewReader(body)
		}
		request, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
		if err != nil {
			return esResponse{}, err
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", client.userAgent)
		if len(body) > 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		if client.secret != nil {
			header, headerErr := client.secret.AuthorizationHeader()
			if headerErr != nil {
				return esResponse{}, headerErr
			}
			request.Header.Set("Authorization", header)
		}
		client.mu.Lock()
		client.requests++
		client.mu.Unlock()
		httpResponse, requestErr := client.http.Do(request)
		if requestErr != nil {
			if attempt < client.retries && retryableStatus(0, requestErr) {
				if waitErr := waitRetry(ctx, retryDelay(path, attempt+1)); waitErr != nil {
					return esResponse{}, waitErr
				}
				continue
			}
			client.mu.Lock()
			client.failed++
			client.mu.Unlock()
			return esResponse{}, redactClientError(requestErr, client.secret)
		}
		payload, readErr := io.ReadAll(io.LimitReader(httpResponse.Body, maxClientResponseBytes+1))
		_ = httpResponse.Body.Close()
		if readErr != nil {
			return esResponse{}, readErr
		}
		if int64(len(payload)) > maxClientResponseBytes {
			return esResponse{}, fmt.Errorf("elasticsearch response exceeds %d bytes", maxClientResponseBytes)
		}
		if attempt < client.retries && retryableStatus(httpResponse.StatusCode, nil) {
			if httpResponse.StatusCode == http.StatusTooManyRequests {
				client.noteSlowdown()
			}
			if waitErr := waitRetry(ctx, retryAfter(httpResponse, path, attempt+1)); waitErr != nil {
				return esResponse{}, waitErr
			}
			continue
		}
		if httpResponse.StatusCode < 200 || httpResponse.StatusCode > 299 {
			client.mu.Lock()
			client.failed++
			client.mu.Unlock()
		} else {
			client.decaySlowdown()
		}
		return esResponse{StatusCode: httpResponse.StatusCode, Body: payload}, nil
	}
}

func (client *esClient) requestURL(path string, query url.Values) (string, error) {
	base, err := client.endpoint.URL()
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	basePath := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if path != "" {
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
			return "", fmt.Errorf("elasticsearch path is invalid")
		}
		parsed.RawPath = ""
		parsed.Path = basePath + path
	}
	if query != nil {
		parsed.RawQuery = query.Encode()
	} else {
		parsed.RawQuery = ""
	}
	parsed.Fragment = ""
	return parsed.String(), nil
}

func allowlistedRequest(method, path string) bool {
	path = strings.TrimSpace(path)
	switch method {
	case http.MethodGet:
		switch path {
		case "", "/", "/_cluster/health", "/_security/_authenticate", "/_cat/indices", "/_alias", "/_data_stream":
			return true
		}
		return strings.HasSuffix(path, "/_mapping") && validResourcePath(path)
	case http.MethodPost:
		return strings.HasSuffix(path, "/_search") && validResourcePath(path)
	default:
		return false
	}
}

func validResourcePath(path string) bool {
	trimmed := strings.Trim(path, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return false
	}
	return validIndexName(parts[0])
}

func validIndexName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 255 {
		return false
	}
	if strings.ContainsAny(name, `/?#\\ *,"<>|,`) {
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	return true
}

func retryableStatus(status int, err error) bool {
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return false
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return true
		}
		kind, ok := transport.KindOf(err)
		if ok {
			switch kind {
			case transport.ErrorTimeout, transport.ErrorDNS, transport.ErrorConnect, transport.ErrorNetwork, transport.ErrorRead:
				return true
			}
		}
		message := strings.ToLower(err.Error())
		return strings.Contains(message, "timeout") || strings.Contains(message, "reset") || strings.Contains(message, "connection")
	}
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func stripRedirectCredentials(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del("Authorization")
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Cookie")
	request.Header.Del("Referer")
}

func (client *esClient) noteSlowdown() {
	if client == nil {
		return
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.slowdown <= 0 {
		client.slowdown = 100 * time.Millisecond
		return
	}
	client.slowdown *= 2
	if client.slowdown > 4*time.Second {
		client.slowdown = 4 * time.Second
	}
}

func (client *esClient) decaySlowdown() {
	if client == nil {
		return
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.slowdown /= 2
	if client.slowdown < 100*time.Millisecond {
		client.slowdown = 0
	}
}

func (client *esClient) waitSlowdown(ctx context.Context) error {
	if client == nil {
		return nil
	}
	client.mu.Lock()
	delay := client.slowdown
	client.mu.Unlock()
	if delay <= 0 {
		return nil
	}
	return waitRetry(ctx, delay)
}

func retryAfter(response *http.Response, path string, attempt int) time.Duration {
	if response != nil {
		if raw := strings.TrimSpace(response.Header.Get("Retry-After")); raw != "" {
			if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 && seconds <= 30 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return retryDelay(path, attempt)
}

func retryDelay(name string, attempt int) time.Duration {
	delay := 200 * time.Millisecond
	for index := 1; index < attempt && delay < 4*time.Second; index++ {
		delay *= 2
	}
	if delay > 4*time.Second {
		delay = 4 * time.Second
	}
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(name))
	_, _ = hasher.Write([]byte(strconv.Itoa(attempt)))
	factor := int64(800 + hasher.Sum32()%401)
	return time.Duration(int64(delay) * factor / 1000)
}

func waitRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func redactClientError(err error, secret *credential.Secret) error {
	if err == nil {
		return nil
	}
	message := credential.Redact(err.Error(), secret)
	if message == err.Error() {
		return err
	}
	return fmt.Errorf("%s", message)
}
