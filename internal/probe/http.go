package probe

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/transport"
)

var retainedHeaderNames = []string{
	"Content-Type",
	"Server",
	"Warning",
	"Www-Authenticate",
	"X-Elastic-Product",
	"X-Found-Handling-Cluster",
	"X-Found-Handling-Instance",
}

// HTTPProber performs one read-only GET through the shared transport.
type HTTPProber struct {
	client *transport.Client
}

// NewHTTP creates a prober backed by a reusable transport client.
func NewHTTP(client *transport.Client) (*HTTPProber, error) {
	if client == nil {
		return nil, errors.New("create HTTP prober: transport client is required")
	}
	return &HTTPProber{client: client}, nil
}

// Probe retrieves an endpoint without retaining request headers or its raw path.
func (prober *HTTPProber) Probe(ctx context.Context, endpoint model.Endpoint) (Result, error) {
	if prober == nil || prober.client == nil {
		return Result{}, &Error{kind: ErrorInvalidEndpoint, cause: errors.New("HTTP prober is not initialized")}
	}
	rawURL, err := endpoint.URL()
	if err != nil {
		return Result{}, &Error{kind: ErrorInvalidEndpoint, cause: err}
	}
	request, err := transport.NewRequest(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Result{}, classifyError(err)
	}
	request.Header.Set("Accept", "application/json")

	response, err := prober.client.Do(request)
	if err != nil {
		return Result{}, classifyError(err)
	}

	return Result{
		Request: RequestMetadata{
			Method:   http.MethodGet,
			Resource: resourceKind(endpoint.Path),
		},
		StatusCode: response.StatusCode,
		Protocol:   response.Protocol,
		Headers:    retainHeaders(response.Header),
		Body:       bytes.Clone(response.Body),
	}, nil
}

func resourceKind(path string) ResourceKind {
	if path == "" || path == "/" {
		return ResourceRoot
	}
	return ResourceCustomPath
}

func retainHeaders(headers http.Header) []HeaderField {
	retained := make([]HeaderField, 0, len(retainedHeaderNames))
	for _, name := range retainedHeaderNames {
		values := headers.Values(name)
		if len(values) == 0 {
			continue
		}
		field := HeaderField{Name: name}
		if len(values) > maxRetainedHeaderValues {
			values = values[:maxRetainedHeaderValues]
			field.Truncated = true
		}

		remaining := maxRetainedHeaderBytes
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			sanitized := sanitizeHeaderValue(value)
			if _, exists := seen[sanitized]; exists {
				continue
			}
			if len(sanitized) > remaining {
				sanitized = truncateUTF8(sanitized, remaining)
				field.Truncated = true
			}
			if sanitized != "" {
				field.Values = append(field.Values, sanitized)
				seen[sanitized] = struct{}{}
				remaining -= len(sanitized)
			}
			if remaining == 0 {
				field.Truncated = true
				break
			}
		}
		sort.Strings(field.Values)
		if len(field.Values) == 0 {
			continue
		}
		retained = append(retained, field)
	}
	return retained
}

func sanitizeHeaderValue(value string) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, value)
	return strings.TrimSpace(value)
}

func truncateUTF8(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

var _ Prober = (*HTTPProber)(nil)
