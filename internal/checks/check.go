package checks

import (
	"github.com/cumakurt/garga/internal/capability"
	"github.com/cumakurt/garga/internal/fingerprint"
	"github.com/cumakurt/garga/internal/model"
)

// Stable check identifiers. IDs are never reused for different semantics.
const (
	CheckTLSNotEnabled                = "garga.tls.not_enabled"
	CheckExposureAnonymousAccess      = "garga.exposure.anonymous_access"
	CheckExposureSecurityUnconfigured = "garga.exposure.security_unconfigured"
	CheckExposurePublicNetwork        = "garga.exposure.public_network"
)

const (
	resourceTransport = "transport"
	resourceAnonymous = "anonymous"
	resourceSecurity  = "security"
	resourceNetwork   = "network"
	productName       = "Elasticsearch"
)

const (
	refTLSSetup      = "https://www.elastic.co/guide/en/elasticsearch/reference/current/configuring-tls.html"
	refMinimalSecure = "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"
)

// Request is an optional HTTP exchange a check would make. WP 5.1 checks make none.
type Request struct {
	Method string
	Path   string
}

// Input is the already-collected, non-secret evidence a check may read.
type Input struct {
	Endpoint     model.Endpoint
	Fingerprint  fingerprint.Result
	Capabilities capability.Result
}

// Check evaluates one security condition without performing I/O.
type Check interface {
	ID() string
	Applies(input Input) bool
	Evaluate(input Input) []model.Finding
	Requests() []Request
}

func productDetected(input Input) bool {
	switch input.Fingerprint.Classification {
	case fingerprint.ClassificationLikely, fingerprint.ClassificationConfirmed:
		return true
	default:
		return false
	}
}

func validTarget(input Input) bool {
	_, err := input.Endpoint.URL()
	return err == nil
}

func applicable(input Input) bool {
	return productDetected(input) && validTarget(input)
}

func baseFinding(checkID, title, resource string, input Input, severity model.Severity, confidence model.Confidence) model.Finding {
	product := input.Fingerprint.Product
	if product == "" {
		product = productName
	}
	version := input.Fingerprint.Version
	if version == "" {
		version = input.Capabilities.Version
	}
	return model.Finding{
		SchemaVersion: model.FindingSchemaVersion,
		ID:            model.FindingID(checkID, input.Endpoint, resource),
		CheckID:       checkID,
		Title:         title,
		Target:        input.Endpoint,
		Product:       product,
		Version:       version,
		Severity:      severity,
		Confidence:    confidence,
		Resource:      resource,
	}
}
