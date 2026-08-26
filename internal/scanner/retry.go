package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"strconv"
	"time"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/probe"
	"github.com/cumakurt/garga/internal/transport"
)

func shouldRetry(result probe.Result, err error) bool {
	if err == nil {
		switch result.StatusCode {
		case 408, 425, 429, 500, 502, 503, 504:
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
	if kind, ok := probe.KindOf(err); ok {
		switch kind {
		case probe.ErrorTimeout, probe.ErrorTCP:
			return true
		case probe.ErrorInvalidEndpoint, probe.ErrorCanceled, probe.ErrorTLS, probe.ErrorHTTP:
			// HTTP read failures are handled below through their transport cause.
		}
	}
	if kind, ok := transport.KindOf(err); ok {
		switch kind {
		case transport.ErrorTimeout, transport.ErrorDNS, transport.ErrorConnect, transport.ErrorNetwork, transport.ErrorRead:
			return true
		default:
			return false
		}
	}
	return false
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
	// A stable 80%..120% factor spreads retries without nondeterministic test output.
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
