package advisory

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxElasticPageBytes = 2 << 20
	maxTopicBytes       = 2 << 20
	maxCVERecordBytes   = 2 << 20
	maxKEVBytes         = 32 << 20
	maxEPSSBytes        = 16 << 20
)

type Fetcher interface {
	Get(context.Context, string, int64) ([]byte, error)
}

type HTTPFetcher struct {
	Client    *http.Client
	UserAgent string
}

func (fetcher HTTPFetcher) Get(ctx context.Context, address string, limit int64) ([]byte, error) {
	parsed, err := url.Parse(address)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("fetch advisory: source URL is invalid")
	}
	client := fetcher.Client
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				if parsed.Scheme == "https" && request.URL.Scheme != "https" {
					return fmt.Errorf("redirect downgraded HTTPS")
				}
				if request.URL.User != nil {
					return fmt.Errorf("redirect URL contains credentials")
				}
				return nil
			},
		}
	}
	userAgent := strings.TrimSpace(fetcher.UserAgent)
	if userAgent == "" {
		userAgent = "garga-advisory-sync/0.1"
	}
	var lastStatus int
	var retryAfter time.Duration
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt-1)) * 250 * time.Millisecond
			if retryAfter > delay {
				delay = retryAfter
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			return nil, fmt.Errorf("fetch advisory: create request: %w", err)
		}
		request.Header.Set("Accept", "application/json, application/gzip, text/csv;q=0.9, */*;q=0.1")
		request.Header.Set("User-Agent", userAgent)
		response, err := client.Do(request)
		if err != nil {
			if attempt < 2 {
				continue
			}
			return nil, fmt.Errorf("fetch advisory: request failed: %w", err)
		}
		lastStatus = response.StatusCode
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			retryAfter = parseRetryAfter(response.Header.Get("Retry-After"), time.Now())
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			_ = response.Body.Close()
			return nil, fmt.Errorf("fetch advisory: server returned HTTP %d", response.StatusCode)
		}
		if response.ContentLength > limit {
			_ = response.Body.Close()
			return nil, fmt.Errorf("fetch advisory: response exceeds %d bytes", limit)
		}
		contents, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			return nil, fmt.Errorf("fetch advisory: read response")
		}
		if int64(len(contents)) > limit {
			return nil, fmt.Errorf("fetch advisory: response exceeds %d bytes", limit)
		}
		return contents, nil
	}
	return nil, fmt.Errorf("fetch advisory: server remained unavailable (HTTP %s)", strconv.Itoa(lastStatus))
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	const maximumRetryAfter = 30 * time.Second

	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds >= int(maximumRetryAfter/time.Second) {
			return maximumRetryAfter
		}
		return min(time.Duration(seconds)*time.Second, maximumRetryAfter)
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return min(when.Sub(now), maximumRetryAfter)
}
