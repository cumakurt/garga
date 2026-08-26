package target

import (
	"context"
	"io"
	"net/netip"
	"strings"

	"github.com/cumakurt/garga/internal/model"
)

// CIDRSource lazily emits every address in a canonical IP prefix, including IPv4 network and
// broadcast addresses. It stores only the prefix and next address.
type CIDRSource struct {
	prefix    netip.Prefix
	next      netip.Addr
	source    string
	exhausted bool
	closed    bool
}

// NewCIDRSource creates a pull-based iterator over an IPv4 or IPv6 prefix.
func NewCIDRSource(rawPrefix, source string) (*CIDRSource, error) {
	input := strings.TrimSpace(rawPrefix)
	if input == "" {
		return nil, newSourceError("create CIDR source: value is empty", nil)
	}
	if len(input) > maxTargetInputBytes {
		return nil, newSourceError("create CIDR source: value exceeds 8192 bytes", nil)
	}

	prefix, err := netip.ParsePrefix(input)
	if err != nil {
		return nil, newSourceError("create CIDR source: invalid IP prefix", err)
	}
	prefix = prefix.Masked()

	return &CIDRSource{
		prefix: prefix,
		next:   prefix.Addr(),
		source: source,
	}, nil
}

// Next returns the next address in the prefix without precomputing remaining addresses.
func (source *CIDRSource) Next(ctx context.Context) (model.Target, error) {
	if err := ctx.Err(); err != nil {
		return model.Target{}, err
	}
	if source.closed || source.exhausted {
		return model.Target{}, io.EOF
	}

	current := source.next
	next := current.Next()
	if !next.IsValid() || !source.prefix.Contains(next) {
		source.exhausted = true
	} else {
		source.next = next
	}

	return model.Target{
		Host:       current.String(),
		SchemeHint: model.SchemeAuto,
		Source:     source.source,
	}, nil
}

// Close stops iteration. It is safe to call more than once.
func (source *CIDRSource) Close() error {
	source.closed = true
	return nil
}
