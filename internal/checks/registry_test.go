package checks

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/capability"
	"github.com/cumakurt/garga/internal/fingerprint"
	"github.com/cumakurt/garga/internal/model"
)

const canary = "credential-canary"

func TestDefaultRegistryIDsAreUniqueAndStable(t *testing.T) {
	t.Parallel()

	want := []string{
		CheckTLSNotEnabled,
		CheckExposureAnonymousAccess,
		CheckExposureSecurityUnconfigured,
		CheckExposurePublicNetwork,
	}
	got := make([]string, 0, len(want))
	seen := make(map[string]struct{}, len(want))
	for _, check := range DefaultRegistry().Checks() {
		id := check.ID()
		if _, exists := seen[id]; exists {
			t.Fatalf("duplicate check ID %q", id)
		}
		seen[id] = struct{}{}
		got = append(got, id)
		if len(check.Requests()) != 0 {
			t.Fatalf("%s declared HTTP requests: %#v", id, check.Requests())
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IDs = %#v, want %#v", got, want)
	}
}

func TestNewRegistryRejectsInvalidChecks(t *testing.T) {
	t.Parallel()

	if _, err := NewRegistry(nil); err == nil {
		t.Fatal("NewRegistry(nil) returned nil error")
	}
	if _, err := NewRegistry(tlsNotEnabled{}, tlsNotEnabled{}); err == nil {
		t.Fatal("NewRegistry() accepted a duplicate ID")
	}
}

func TestEvaluateOpenPlaintextPublicCluster(t *testing.T) {
	t.Parallel()

	input := Input{
		Endpoint:     model.Endpoint{Scheme: model.SchemeHTTP, Host: "203.0.113.10", Port: 9200},
		Fingerprint:  confirmedIdentity(),
		Capabilities: openWithoutSecurity(),
	}
	findings := DefaultRegistry().Evaluate(input)
	got := checkIDs(findings)
	want := []string{
		CheckExposureAnonymousAccess,
		CheckExposurePublicNetwork,
		CheckExposureSecurityUnconfigured,
		CheckTLSNotEnabled,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("check IDs = %#v, want %#v", got, want)
	}
	for _, finding := range findings {
		if finding.SchemaVersion != model.FindingSchemaVersion || finding.Product != "Elasticsearch" || finding.Version != "9.4.4" {
			t.Fatalf("finding metadata = %#v", finding)
		}
		if finding.ID != model.FindingID(finding.CheckID, input.Endpoint, finding.Resource) {
			t.Fatalf("unstable ID: %#v", finding)
		}
		if finding.CheckID == CheckExposureAnonymousAccess {
			if finding.Severity != model.SeverityHigh || finding.Confidence != model.ConfidenceMedium {
				t.Fatalf("anonymous classification = %#v", finding)
			}
			if !containsEvidence(finding, "class_write_inferred") || !containsTag(finding, "inferred") {
				t.Fatalf("open cluster was not labeled inferred write: %#v", finding)
			}
		}
	}
}

func TestEvaluateAuthenticatedPrivateHTTPSIsSilent(t *testing.T) {
	t.Parallel()

	input := Input{
		Endpoint:     model.Endpoint{Scheme: model.SchemeHTTPS, Host: "192.168.1.10", Port: 9200},
		Fingerprint:  confirmedIdentity(),
		Capabilities: authenticatedWithSecurity(),
	}
	if findings := DefaultRegistry().Evaluate(input); findings != nil {
		t.Fatalf("findings = %#v, want none", findings)
	}
}

func TestCheckApplicability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  Input
		wantID string
		want   bool
	}{
		{
			name: "possible fingerprint skips TLS",
			input: Input{
				Endpoint:    model.Endpoint{Scheme: model.SchemeHTTP, Host: "203.0.113.10", Port: 9200},
				Fingerprint: fingerprint.Result{Classification: fingerprint.ClassificationPossible},
			},
			wantID: CheckTLSNotEnabled,
		},
		{
			name: "HTTPS skips TLS",
			input: Input{
				Endpoint:    model.Endpoint{Scheme: model.SchemeHTTPS, Host: "203.0.113.10", Port: 9200},
				Fingerprint: confirmedIdentity(),
			},
			wantID: CheckTLSNotEnabled,
		},
		{
			name: "auth required skips anonymous",
			input: Input{
				Endpoint:     model.Endpoint{Scheme: model.SchemeHTTPS, Host: "192.168.1.10", Port: 9200},
				Fingerprint:  confirmedIdentity(),
				Capabilities: authenticatedWithSecurity(),
			},
			wantID: CheckExposureAnonymousAccess,
		},
		{
			name: "unknown security skips unconfigured",
			input: Input{
				Endpoint:     model.Endpoint{Scheme: model.SchemeHTTPS, Host: "192.168.1.10", Port: 9200},
				Fingerprint:  confirmedIdentity(),
				Capabilities: capability.Result{},
			},
			wantID: CheckExposureSecurityUnconfigured,
		},
		{
			name: "hostname skips public network",
			input: Input{
				Endpoint:    model.Endpoint{Scheme: model.SchemeHTTPS, Host: "es.example.com", Port: 9200},
				Fingerprint: confirmedIdentity(),
			},
			wantID: CheckExposurePublicNetwork,
		},
		{
			name: "loopback skips public network",
			input: Input{
				Endpoint:    model.Endpoint{Scheme: model.SchemeHTTP, Host: "127.0.0.1", Port: 9200},
				Fingerprint: confirmedIdentity(),
			},
			wantID: CheckExposurePublicNetwork,
		},
		{
			name: "likely HTTP applies TLS",
			input: Input{
				Endpoint:    model.Endpoint{Scheme: model.SchemeHTTP, Host: "10.0.0.10", Port: 9200},
				Fingerprint: fingerprint.Result{Classification: fingerprint.ClassificationLikely},
			},
			wantID: CheckTLSNotEnabled,
			want:   true,
		},
		{
			name: "invalid endpoint skips all",
			input: Input{
				Endpoint:    model.Endpoint{Host: "203.0.113.10"},
				Fingerprint: confirmedIdentity(),
			},
			wantID: CheckTLSNotEnabled,
		},
	}

	registry := DefaultRegistry()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			for _, check := range registry.Checks() {
				if check.ID() != test.wantID {
					continue
				}
				if got := check.Applies(test.input); got != test.want {
					t.Fatalf("Applies() = %t, want %t", got, test.want)
				}
				return
			}
			t.Fatalf("check %s not found", test.wantID)
		})
	}
}

func TestEvaluateDoesNotCopyResponseBodiesOrCapabilityDetails(t *testing.T) {
	t.Parallel()

	input := Input{
		Endpoint: model.Endpoint{Scheme: model.SchemeHTTP, Host: "203.0.113.10", Port: 9200},
		Fingerprint: fingerprint.Result{
			Product:        "Elasticsearch",
			Version:        "9.4.4",
			Classification: fingerprint.ClassificationConfirmed,
			Signals: []fingerprint.Signal{{
				Name:   "elastic_cluster_identity",
				Weight: 10,
				Match:  true,
				Detail: canary,
			}},
		},
		Capabilities: capability.Result{
			Version: "9.4.4",
			Capabilities: []capability.Capability{
				{Name: capability.NameAnonymous, Availability: capability.AvailabilityAvailable, Detail: canary},
				{Name: capability.NameSecurity, Availability: capability.AvailabilityUnsupported, Detail: canary},
			},
		},
	}
	findings := DefaultRegistry().Evaluate(input)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	payload, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	rendered := fmt.Sprintf("%+v%s", findings, payload)
	if strings.Contains(rendered, canary) {
		t.Fatalf("findings exposed canary: %s", rendered)
	}
}

func TestEvaluateIsDeterministic(t *testing.T) {
	t.Parallel()

	input := Input{
		Endpoint:     model.Endpoint{Scheme: model.SchemeHTTP, Host: "203.0.113.10", Port: 9200, Path: "/elastic"},
		Fingerprint:  confirmedIdentity(),
		Capabilities: openWithoutSecurity(),
	}
	first := DefaultRegistry().Evaluate(input)
	second := DefaultRegistry().Evaluate(input)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Evaluate() changed:\n%#v\n%#v", first, second)
	}
}

func TestActiveSafeContractForbidsStateChangingRequests(t *testing.T) {
	t.Parallel()

	for _, check := range DefaultRegistry().Checks() {
		for _, request := range check.Requests() {
			if request.Method != http.MethodGet {
				t.Fatalf("%s method = %q", check.ID(), request.Method)
			}
			if !capability.IsAllowlistedAPIPath(request.Path) {
				t.Fatalf("%s path %q is not allowlisted", check.ID(), request.Path)
			}
		}
	}
}

func TestNilRegistryIsSafe(t *testing.T) {
	t.Parallel()

	var registry *Registry
	if registry.Evaluate(Input{}) != nil || registry.Checks() != nil {
		t.Fatal("nil registry produced output")
	}
}

func TestPublicAddressClassification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		host string
		want bool
	}{
		{"203.0.113.10", true},
		{"2001:4860:4860::8888", true},
		{"192.168.1.10", false},
		{"10.0.0.1", false},
		{"127.0.0.1", false},
		{"::1", false},
		{"169.254.1.1", false},
		{"fc00::1", false},
		{"0.0.0.0", false},
		{"es.example.com", false},
		{"::ffff:192.168.0.10", false},
	}
	for _, test := range tests {
		_, got := publicAddress(test.host)
		if got != test.want {
			t.Fatalf("publicAddress(%q) = %t, want %t", test.host, got, test.want)
		}
	}
}

func confirmedIdentity() fingerprint.Result {
	return fingerprint.Result{
		Product:        "Elasticsearch",
		Version:        "9.4.4",
		Score:          100,
		Classification: fingerprint.ClassificationConfirmed,
		Detected:       true,
		Threshold:      80,
	}
}

func openWithoutSecurity() capability.Result {
	return capability.Result{
		Version: "9.4.4",
		Capabilities: []capability.Capability{
			{Name: capability.NameAnonymous, Availability: capability.AvailabilityAvailable, StatusCode: 200},
			{Name: capability.NameSecurity, Availability: capability.AvailabilityUnsupported, StatusCode: 404},
		},
	}
}

func authenticatedWithSecurity() capability.Result {
	return capability.Result{
		Version: "9.4.4",
		Capabilities: []capability.Capability{
			{Name: capability.NameAnonymous, Availability: capability.AvailabilityAuthRequired, StatusCode: 401},
			{Name: capability.NameSecurity, Availability: capability.AvailabilityAuthRequired, StatusCode: 401},
			{Name: capability.NameBasicAuth, Availability: capability.AvailabilityAvailable},
		},
	}
}

func checkIDs(findings []model.Finding) []string {
	ids := make([]string, len(findings))
	for index, finding := range findings {
		ids[index] = finding.CheckID
	}
	return ids
}
