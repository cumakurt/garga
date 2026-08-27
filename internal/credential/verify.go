package credential

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/cumakurt/garga/internal/capability"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/transport"
)

// Elasticsearch Authenticate is GET /_security/_authenticate (since 5.5.0).
// GET /_security/user/_authenticate is Get User for username "_authenticate"
// and returns 404 even when the credential is valid.

// Outcome is a secret-free verification result.
type Outcome string

const (
	OutcomeValid               Outcome = "valid"
	OutcomeInvalid             Outcome = "invalid"
	OutcomeSecurityUnavailable Outcome = "security_unavailable"
)

// Result reports whether one explicit credential was accepted.
type Result struct {
	Outcome    Outcome
	Mechanism  Kind
	StatusCode int
}

// Verifier performs one GET against the security authenticate API.
type Verifier struct {
	client *transport.Client
}

// NewVerifier creates a verifier that reuses the shared transport client.
func NewVerifier(client *transport.Client) (*Verifier, error) {
	if client == nil {
		return nil, fmt.Errorf("create credential verifier: transport client is required")
	}
	return &Verifier{client: client}, nil
}

// Verify sends one authenticated GET and never retries authentication failures.
func (verifier *Verifier) Verify(ctx context.Context, endpoint model.Endpoint, secret *Secret) (Result, error) {
	if verifier == nil || verifier.client == nil {
		return Result{}, fmt.Errorf("verify credential: verifier is not initialized")
	}
	if ctx == nil {
		return Result{}, fmt.Errorf("verify credential: context is required")
	}
	if secret == nil {
		return Result{}, fmt.Errorf("verify credential: secret is required")
	}

	rawURL, err := authenticateURL(endpoint)
	if err != nil {
		return Result{}, err
	}
	header, err := secret.AuthorizationHeader()
	if err != nil {
		return Result{}, err
	}

	request, err := transport.NewRequest(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Result{}, redactError(err, secret)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", header)

	response, err := verifier.client.Do(request)
	if err != nil {
		return Result{}, redactError(err, secret)
	}
	defer zero(response.Body)

	result := Result{Mechanism: secret.Kind(), StatusCode: response.StatusCode}
	switch {
	case response.StatusCode >= 200 && response.StatusCode <= 299:
		result.Outcome = OutcomeValid
	case response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden:
		result.Outcome = OutcomeInvalid
	case response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusNotFound ||
		response.StatusCode == http.StatusMethodNotAllowed || response.StatusCode == http.StatusNotImplemented:
		result.Outcome = OutcomeSecurityUnavailable
	default:
		return result, fmt.Errorf("verify credential: unexpected HTTP status %d", response.StatusCode)
	}
	return result, nil
}

func authenticateURL(endpoint model.Endpoint) (string, error) {
	joined, err := joinAPIPath(endpoint.Path, capability.PathAuthenticate)
	if err != nil {
		return "", err
	}
	endpoint.Path = joined
	rawURL, err := endpoint.URL()
	if err != nil {
		return "", fmt.Errorf("verify credential: endpoint is invalid")
	}
	return rawURL, nil
}

func joinAPIPath(basePath, apiPath string) (string, error) {
	if apiPath != capability.PathAuthenticate {
		return "", fmt.Errorf("verify credential: API path is not allowlisted")
	}
	basePath = strings.TrimSuffix(basePath, "/")
	if basePath == "" {
		return apiPath, nil
	}
	if !strings.HasPrefix(basePath, "/") {
		return "", fmt.Errorf("verify credential: base path is invalid")
	}
	if strings.ContainsAny(basePath, "?#") {
		return "", fmt.Errorf("verify credential: API path must not include a query or fragment")
	}
	return basePath + apiPath, nil
}
