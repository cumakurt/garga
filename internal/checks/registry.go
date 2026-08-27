package checks

import (
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/vulnerability"
)

// Registry evaluates a fixed, ordered set of checks and deduplicates findings.
type Registry struct {
	checks []Check
}

// NewRegistry rejects duplicate check IDs.
func NewRegistry(checks ...Check) (*Registry, error) {
	seen := make(map[string]struct{}, len(checks))
	cloned := make([]Check, 0, len(checks))
	for _, check := range checks {
		if check == nil {
			return nil, errNilCheck
		}
		id := check.ID()
		if id == "" {
			return nil, errEmptyCheckID
		}
		if _, exists := seen[id]; exists {
			return nil, errDuplicateCheckID
		}
		seen[id] = struct{}{}
		cloned = append(cloned, check)
	}
	return &Registry{checks: cloned}, nil
}

// DefaultRegistry returns the TLS, exposure, and anonymous-classification checks.
// It does not load vulnerability signatures.
func DefaultRegistry() *Registry {
	return &Registry{checks: []Check{
		tlsNotEnabled{},
		anonymousAccess{},
		securityUnconfigured{},
		publicNetwork{},
	}}
}

// Checks returns the registered checks in registration order.
func (registry *Registry) Checks() []Check {
	if registry == nil {
		return nil
	}
	return append([]Check(nil), registry.checks...)
}

// Evaluate runs applicable checks and returns deduplicated findings.
func (registry *Registry) Evaluate(input Input) []model.Finding {
	if registry == nil {
		return nil
	}
	var findings []model.Finding
	for _, check := range registry.checks {
		if !check.Applies(input) {
			continue
		}
		findings = append(findings, check.Evaluate(input)...)
	}
	return model.DeduplicateFindings(findings)
}

type registryError string

func (err registryError) Error() string { return string(err) }

const (
	errNilCheck         registryError = "create check registry: check is required"
	errEmptyCheckID     registryError = "create check registry: check ID is required"
	errDuplicateCheckID registryError = "create check registry: check ID is duplicated"
	errNoSignatures     registryError = "create signature registry: at least one signature is required"
)

// SignatureRegistry evaluates only YAML signatures. It does not include TLS or exposure checks.
func SignatureRegistry(signatures []vulnerability.Signature) (*Registry, error) {
	if len(signatures) == 0 {
		return nil, errNoSignatures
	}
	return NewRegistry(signatureCheck{signatures: signatures})
}
