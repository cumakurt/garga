package probe

import (
	"context"

	"github.com/cumakurt/garga/internal/model"
)

const (
	maxRetainedHeaderValues = 8
	maxRetainedHeaderBytes  = 1024
)

// Prober retrieves one bounded response without applying product semantics.
type Prober interface {
	Probe(ctx context.Context, endpoint model.Endpoint) (Result, error)
}

// Result retains only deterministic response data needed by fingerprinting.
type Result struct {
	Request    RequestMetadata
	StatusCode int
	Protocol   string
	Headers    []HeaderField
	Body       []byte
}

// RequestMetadata deliberately omits URL, host, query, and headers.
type RequestMetadata struct {
	Method   string
	Resource ResourceKind
}

// ResourceKind identifies endpoint semantics without retaining a user-supplied path.
type ResourceKind string

const (
	ResourceRoot       ResourceKind = "root"
	ResourceCustomPath ResourceKind = "custom_path"
)

// HeaderField is one allowlisted, bounded response header.
type HeaderField struct {
	Name      string
	Values    []string
	Truncated bool
}
