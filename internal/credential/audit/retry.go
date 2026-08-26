package audit

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"net/http"
	"strconv"
	"time"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/transport"
)

func shouldRetry(statusCode int, err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	if retryableStatus(statusCode) {
		return true
	}
	if err == nil {
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

func retryableStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func retryDelay(options Options, endpoint model.Endpoint, retryNumber int) time.Duration {
	delay := options.RetryBaseBackoff
	for index := 1; index < retryNumber && delay < options.RetryMaxBackoff; index++ {
		if delay > options.RetryMaxBackoff/2 {
			delay = options.RetryMaxBackoff
			break
		}
		delay *= 2
	}

	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(endpoint.Host))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(strconv.Itoa(endpoint.Port)))
	var retryBytes [8]byte
	binary.LittleEndian.PutUint64(retryBytes[:], uint64(retryNumber))
	_, _ = hasher.Write(retryBytes[:])
	factorPermille := int64(800 + hasher.Sum32()%401)
	delay = time.Duration(int64(delay) * factorPermille / 1000)
	if delay > options.RetryMaxBackoff {
		return options.RetryMaxBackoff
	}
	return delay
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
