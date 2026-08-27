package credential

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/capability"
	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/transport"
)

func TestVerifyOutcomes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		want   Outcome
	}{
		{"valid", http.StatusOK, OutcomeValid},
		{"invalid", http.StatusUnauthorized, OutcomeInvalid},
		{"forbidden", http.StatusForbidden, OutcomeInvalid},
		{"missing", http.StatusNotFound, OutcomeSecurityUnavailable},
		{"disabled", http.StatusBadRequest, OutcomeSecurityUnavailable},
		{"method_not_allowed", http.StatusMethodNotAllowed, OutcomeSecurityUnavailable},
		{"not_implemented", http.StatusNotImplemented, OutcomeSecurityUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			const canary = "credential-canary"
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet {
					t.Errorf("method = %q", request.Method)
				}
				if request.URL.RawQuery != "" {
					t.Errorf("query = %q", request.URL.RawQuery)
				}
				if !strings.HasSuffix(request.URL.Path, capability.PathAuthenticate) {
					t.Errorf("path = %q", request.URL.Path)
				}
				if !strings.HasPrefix(request.Header.Get("Authorization"), "Basic ") {
					t.Errorf("missing Authorization")
				}
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, `{"error":"`+canary+`"}`)
			}))
			defer server.Close()

			secret, err := NewBasic("alice", []byte(canary))
			if err != nil {
				t.Fatalf("NewBasic() error = %v", err)
			}
			result, err := newTestVerifier(t).Verify(context.Background(), endpointForServer(t, server.URL), secret)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Outcome != test.want || result.Mechanism != KindBasic || result.StatusCode != test.status {
				t.Fatalf("Verify() = %#v", result)
			}
			if rendered := fmt.Sprintf("%+v", result); strings.Contains(rendered, canary) {
				t.Fatalf("result leaked canary: %s", rendered)
			}
		})
	}
}

func TestVerifyHonorsBasePathAndRejectsUnexpectedStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/elastic/_security/_authenticate" {
			t.Errorf("path = %q", request.URL.Path)
		}
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	secret, err := NewAPIKey([]byte("encoded-key"))
	if err != nil {
		t.Fatalf("NewAPIKey() error = %v", err)
	}
	endpoint := endpointForServer(t, server.URL)
	endpoint.Path = "/elastic"
	_, err = newTestVerifier(t).Verify(context.Background(), endpoint, secret)
	if err == nil || !strings.Contains(err.Error(), "unexpected HTTP status") {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifyDoesNotRetryUnauthorized(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	secret, err := NewBasic("alice", []byte("credential-canary"))
	if err != nil {
		t.Fatalf("NewBasic() error = %v", err)
	}
	result, err := newTestVerifier(t).Verify(context.Background(), endpointForServer(t, server.URL), secret)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
	if result.Outcome != OutcomeInvalid || result.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Verify() = %#v", result)
	}
}

func TestAuthenticatePathIsOfficialSecurityAPI(t *testing.T) {
	t.Parallel()
	if capability.PathAuthenticate != "/_security/_authenticate" {
		t.Fatalf("PathAuthenticate = %q, want /_security/_authenticate", capability.PathAuthenticate)
	}
	if !capability.IsAllowlistedAPIPath(capability.PathAuthenticate) {
		t.Fatal("PathAuthenticate is missing from the GET catalog")
	}
	if capability.IsAllowlistedAPIPath("/_security/user/_authenticate") {
		t.Fatal("Get User /_security/user/{username} would 404 for username _authenticate")
	}
	if _, err := joinAPIPath("", "/_security/user/_authenticate"); err == nil {
		t.Fatal("joinAPIPath accepted Get User")
	}
}

func TestVerifyRequiresInputs(t *testing.T) {
	t.Parallel()

	if _, err := NewVerifier(nil); err == nil {
		t.Fatal("NewVerifier(nil) succeeded")
	}
	verifier := newTestVerifier(t)
	secret, err := NewBasic("alice", []byte("secret-value"))
	if err != nil {
		t.Fatalf("NewBasic() error = %v", err)
	}
	if _, err := verifier.Verify(nil, model.Endpoint{}, secret); err == nil { //nolint:staticcheck // nil context must be rejected
		t.Fatal("Verify(nil context) succeeded")
	}
	if _, err := verifier.Verify(context.Background(), model.Endpoint{}, nil); err == nil {
		t.Fatal("Verify(nil secret) succeeded")
	}
}

func newTestVerifier(t *testing.T) *Verifier {
	t.Helper()
	options, err := transport.OptionsFromConfig(config.Defaults(), "garga/credential-test")
	if err != nil {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
	options.DisableEnvironmentProxy = true
	options.RequestTimeout = time.Second
	options.ResponseHeaderTimeout = time.Second
	factory, err := transport.NewFactory(options)
	if err != nil {
		t.Fatalf("NewFactory() error = %v", err)
	}
	t.Cleanup(factory.CloseIdleConnections)
	verifier, err := NewVerifier(factory.Client())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	return verifier
}

func endpointForServer(t *testing.T, rawURL string) model.Endpoint {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	var portNumber int
	if _, err := fmt.Sscanf(request.URL.Port(), "%d", &portNumber); err != nil {
		t.Fatalf("parse server port: %v", err)
	}
	return model.Endpoint{Scheme: model.SchemeHTTP, Host: request.URL.Hostname(), Port: portNumber}
}
