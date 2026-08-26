package capability

import (
	"testing"

	"github.com/cumakurt/garga/internal/fingerprint"
	"github.com/cumakurt/garga/internal/probe"
)

func TestClassifyHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		status int
		want   Availability
	}{
		{200, AvailabilityAvailable},
		{204, AvailabilityAvailable},
		{401, AvailabilityAuthRequired},
		{403, AvailabilityAuthRequired},
		{400, AvailabilityUnsupported},
		{404, AvailabilityUnsupported},
		{405, AvailabilityUnsupported},
		{406, AvailabilityUnsupported},
		{410, AvailabilityUnsupported},
		{501, AvailabilityUnsupported},
		{429, AvailabilityUnknown},
		{500, AvailabilityUnknown},
		{503, AvailabilityUnknown},
		{0, AvailabilityUnknown},
		{418, AvailabilityUnknown},
	}
	for _, test := range tests {
		if got := classifyHTTP(test.status); got != test.want {
			t.Fatalf("classifyHTTP(%d) = %q, want %q", test.status, got, test.want)
		}
	}
}

func TestClassifyProbeErrorDoesNotSuppress(t *testing.T) {
	t.Parallel()

	capability := classifyProbe(NameHealth, probe.Result{}, errProbeFailed{})
	if capability.Availability != AvailabilityError || capability.Detail != "probe_error" {
		t.Fatalf("classifyProbe() = %#v", capability)
	}
	result := emptyResult("9.4.4")
	setCapability(&result, capability)
	if result.Suppresses(NameHealth) || result.Exists(NameHealth) {
		t.Fatalf("probe errors must not look like unsupported APIs: %#v", result)
	}
}

func TestAdvertisedMechanismsIgnoreNonSecurityRealms(t *testing.T) {
	t.Parallel()

	basic, apiKey := advertisedMechanisms([]probe.HeaderField{
		{Name: "Www-Authenticate", Values: []string{`Basic realm="credential-canary"`, "ApiKey"}},
		{Name: "Server", Values: []string{"credential-canary"}},
	})
	if basic {
		t.Fatal("non-security Basic realm was treated as Elasticsearch Basic Auth")
	}
	if !apiKey {
		t.Fatal("ApiKey challenge was ignored")
	}
}

func TestEligibleClassifications(t *testing.T) {
	t.Parallel()

	tests := []struct {
		class fingerprint.Classification
		want  bool
	}{
		{fingerprint.ClassificationUnknown, false},
		{fingerprint.ClassificationPossible, false},
		{fingerprint.ClassificationLikely, true},
		{fingerprint.ClassificationConfirmed, true},
	}
	for _, test := range tests {
		got := eligible(fingerprint.Result{Classification: test.class})
		if got != test.want {
			t.Fatalf("eligible(%s) = %t, want %t", test.class, got, test.want)
		}
	}
}

type errProbeFailed struct{}

func (errProbeFailed) Error() string { return "probe failed: HTTP error" }
