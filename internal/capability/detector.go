package capability

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/cumakurt/garga/internal/fingerprint"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/probe"
)

// Detector discovers Elasticsearch capabilities through the shared probe transport.
type Detector struct {
	prober probe.Prober
}

// New creates a detector that reuses one product-neutral prober.
func New(prober probe.Prober) (*Detector, error) {
	if prober == nil {
		return nil, errors.New("create capability detector: prober is required")
	}
	return &Detector{prober: prober}, nil
}

// Discover classifies allowlisted read-only APIs for one likely or confirmed endpoint.
// It reuses the fingerprint root probe and never issues a state-changing request.
func (detector *Detector) Discover(
	ctx context.Context,
	endpoint model.Endpoint,
	identity fingerprint.Result,
	root probe.Result,
) (Result, error) {
	if detector == nil || detector.prober == nil {
		return Result{}, errors.New("discover capabilities: detector is not initialized")
	}
	if ctx == nil {
		return Result{}, errors.New("discover capabilities: context is required")
	}
	if !eligible(identity) {
		return ineligibleResult(identity.Version), nil
	}

	result := emptyResult(identity.Version)
	setCapability(&result, classifyProbe(NameRoot, root, nil))

	var sawChallenge, basicAuth, apiKey bool
	if root.StatusCode == http.StatusUnauthorized || root.StatusCode == http.StatusForbidden {
		sawChallenge = true
		basicAuth, apiKey = advertisedMechanisms(root.Headers)
	}

	for _, spec := range extraProbes {
		if err := ctx.Err(); err != nil {
			deriveAuthentication(&result, sawChallenge, basicAuth, apiKey)
			return result, canceledError(err)
		}

		apiEndpoint, err := endpointForAPI(endpoint, spec.path)
		if err != nil {
			setCapability(&result, Capability{Name: spec.name, Availability: AvailabilityError, Detail: "probe_error"})
			continue
		}

		response, probeErr := detector.prober.Probe(ctx, apiEndpoint)
		if probeErr != nil {
			if kind, ok := probe.KindOf(probeErr); ok && kind == probe.ErrorCanceled {
				deriveAuthentication(&result, sawChallenge, basicAuth, apiKey)
				return result, canceledError(probeErr)
			}
			if errors.Is(probeErr, context.Canceled) {
				deriveAuthentication(&result, sawChallenge, basicAuth, apiKey)
				return result, canceledError(probeErr)
			}
			setCapability(&result, classifyProbe(spec.name, response, probeErr))
			continue
		}

		setCapability(&result, classifyProbe(spec.name, response, nil))
		if spec.name == NameSecurity && response.StatusCode >= 200 && response.StatusCode <= 299 {
			result.AnonymousSuperuser = parseAnonymousSuperuser(response.Body)
		}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			sawChallenge = true
			probeBasic, probeAPIKey := advertisedMechanisms(response.Headers)
			basicAuth = basicAuth || probeBasic
			apiKey = apiKey || probeAPIKey
		}
	}

	deriveAuthentication(&result, sawChallenge, basicAuth, apiKey)
	return result, nil
}

func endpointForAPI(endpoint model.Endpoint, apiPath string) (model.Endpoint, error) {
	joined, err := joinAPIPath(endpoint.Path, apiPath)
	if err != nil {
		return model.Endpoint{}, err
	}
	endpoint.Path = joined
	if _, err := endpoint.URL(); err != nil {
		return model.Endpoint{}, err
	}
	return endpoint, nil
}

func canceledError(cause error) error {
	if cause == nil {
		cause = context.Canceled
	}
	return fmt.Errorf("discover capabilities: operation canceled: %w", cause)
}
