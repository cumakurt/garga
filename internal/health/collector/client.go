package collector

import (
	"context"
	"errors"
	"hash/fnv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/ratelimit"
	"github.com/cumakurt/garga/internal/transport"
)

type client struct {
	transport *transport.Client
	endpoint  model.Endpoint
	secret    *credential.Secret
	limiter   *ratelimit.Limiter
	retries   int

	mu       sync.Mutex
	requests int
	bytes    int64
	failed   int
	retried  int
}

func newClient(transportClient *transport.Client, endpoint model.Endpoint, secret *credential.Secret, rate float64, retries int) (*client, error) {
	if transportClient == nil {
		return nil, wrap(ErrorConfiguration, errors.New("transport client is required"))
	}
	if _, err := endpoint.URL(); err != nil {
		return nil, wrap(ErrorConfiguration, err)
	}
	limiter, err := ratelimit.New(rate, rate)
	if err != nil {
		return nil, wrap(ErrorConfiguration, err)
	}
	if retries < 0 || retries > 10 {
		return nil, wrap(ErrorConfiguration, errors.New("retry count is invalid"))
	}
	return &client{transport: transportClient, endpoint: endpoint, secret: secret, limiter: limiter, retries: retries}, nil
}

func (client *client) get(ctx context.Context, spec requestSpec) (transport.Response, error) {
	rawURL, err := client.requestURL(spec)
	if err != nil {
		return transport.Response{}, err
	}
	for attempt := 0; ; attempt++ {
		if err := client.limiter.Wait(ctx, client.endpoint.Host); err != nil {
			return transport.Response{}, err
		}
		request, requestErr := transport.NewRequest(ctx, http.MethodGet, rawURL, nil)
		if requestErr != nil {
			return transport.Response{}, requestErr
		}
		request.Header.Set("Accept", "application/json")
		if client.secret != nil {
			header, headerErr := client.secret.AuthorizationHeader()
			if headerErr != nil {
				return transport.Response{}, wrap(ErrorConfiguration, headerErr)
			}
			request.Header.Set("Authorization", header)
		}

		client.mu.Lock()
		client.requests++
		client.mu.Unlock()
		response, requestErr := client.transport.Do(request)
		if requestErr == nil {
			client.mu.Lock()
			client.bytes += int64(len(response.Body))
			client.mu.Unlock()
		}
		if attempt >= client.retries || !retryable(response.StatusCode, requestErr) {
			if requestErr != nil || response.StatusCode < 200 || response.StatusCode > 299 {
				client.mu.Lock()
				client.failed++
				client.mu.Unlock()
			}
			return response, requestErr
		}
		client.mu.Lock()
		client.retried++
		client.mu.Unlock()
		if err := waitRetry(ctx, retryDelay(spec.Name, attempt+1)); err != nil {
			return transport.Response{}, err
		}
	}
}

func (client *client) requestURL(spec requestSpec) (string, error) {
	base, err := client.endpoint.URL()
	if err != nil {
		return "", wrap(ErrorConfiguration, err)
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", wrap(ErrorConfiguration, err)
	}
	basePath := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if spec.Path != "" {
		if !strings.HasPrefix(spec.Path, "/") || strings.ContainsAny(spec.Path, "?#") {
			return "", wrap(ErrorConfiguration, errors.New("health API path is invalid"))
		}
		parsed.RawPath = ""
		parsed.Path = basePath + spec.Path
	}
	parsed.RawQuery = spec.Query.Encode()
	parsed.Fragment = ""
	return parsed.String(), nil
}

func (client *client) telemetry() (requests int, bytes int64, failed, retried int) {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.requests, client.bytes, client.failed, client.retried
}

func retryable(status int, err error) bool {
	if err == nil {
		switch status {
		case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
			http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		default:
			return false
		}
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	kind, ok := transport.KindOf(err)
	if !ok {
		return false
	}
	switch kind {
	case transport.ErrorTimeout, transport.ErrorDNS, transport.ErrorConnect, transport.ErrorNetwork, transport.ErrorRead:
		return true
	default:
		return false
	}
}

func retryDelay(name string, attempt int) time.Duration {
	delay := 100 * time.Millisecond
	for index := 1; index < attempt && delay < 2*time.Second; index++ {
		delay *= 2
	}
	if delay > 2*time.Second {
		delay = 2 * time.Second
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
