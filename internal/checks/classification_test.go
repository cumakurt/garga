package checks

import (
	"strings"
	"testing"

	"github.com/cumakurt/garga/internal/capability"
	"github.com/cumakurt/garga/internal/model"
)

func TestClassifyAnonymousAccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input capability.Result
		want  AnonymousClassification
	}{
		{
			name:  "none",
			input: authenticatedWithSecurity(),
			want:  AnonymousClassification{Class: AccessNone},
		},
		{
			name: "metadata",
			input: capability.Result{Capabilities: []capability.Capability{
				{Name: capability.NameAnonymous, Availability: capability.AvailabilityAvailable},
				{Name: capability.NameRoot, Availability: capability.AvailabilityAvailable},
				{Name: capability.NameHealth, Availability: capability.AvailabilityAvailable},
				{Name: capability.NameSecurity, Availability: capability.AvailabilityAuthRequired},
			}},
			want: AnonymousClassification{Class: AccessMetadata},
		},
		{
			name: "read",
			input: capability.Result{Capabilities: []capability.Capability{
				{Name: capability.NameAnonymous, Availability: capability.AvailabilityAvailable},
				{Name: capability.NameIndices, Availability: capability.AvailabilityAvailable},
				{Name: capability.NameSecurity, Availability: capability.AvailabilityAvailable},
			}},
			want: AnonymousClassification{Class: AccessRead},
		},
		{
			name:  "write inferred",
			input: openWithoutSecurity(),
			want:  AnonymousClassification{Class: AccessWrite, Inferred: true},
		},
		{
			name: "admin inferred",
			input: capability.Result{Capabilities: []capability.Capability{
				{Name: capability.NameAnonymous, Availability: capability.AvailabilityAvailable},
				{Name: capability.NameSecurity, Availability: capability.AvailabilityUnsupported},
				{Name: capability.NameState, Availability: capability.AvailabilityAvailable},
			}},
			want: AnonymousClassification{Class: AccessAdmin, Inferred: true},
		},
		{
			name: "admin confirmed superuser",
			input: capability.Result{
				AnonymousSuperuser: true,
				Capabilities: []capability.Capability{
					{Name: capability.NameAnonymous, Availability: capability.AvailabilityAvailable},
					{Name: capability.NameSecurity, Availability: capability.AvailabilityAvailable},
				},
			},
			want: AnonymousClassification{Class: AccessAdmin, Inferred: false},
		},
		{
			name: "superuser wins over missing cluster APIs",
			input: capability.Result{
				AnonymousSuperuser: true,
				Capabilities: []capability.Capability{
					{Name: capability.NameAnonymous, Availability: capability.AvailabilityAvailable},
					{Name: capability.NameSecurity, Availability: capability.AvailabilityUnsupported},
				},
			},
			want: AnonymousClassification{Class: AccessAdmin, Inferred: false},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyAnonymousAccess(test.input)
			if got != test.want {
				t.Fatalf("ClassifyAnonymousAccess() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestAnonymousFindingLabelsInferredWriteAndAdmin(t *testing.T) {
	t.Parallel()

	endpoint := model.Endpoint{Scheme: model.SchemeHTTPS, Host: "192.168.1.10", Port: 9200}
	identity := confirmedIdentity()

	writeFinding := anonymousAccess{}.Evaluate(Input{
		Endpoint:     endpoint,
		Fingerprint:  identity,
		Capabilities: openWithoutSecurity(),
	})
	if len(writeFinding) != 1 || writeFinding[0].Severity != model.SeverityHigh || writeFinding[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("write finding = %#v", writeFinding)
	}
	if !containsTag(writeFinding[0], "inferred") || !containsEvidence(writeFinding[0], "class_write_inferred") {
		t.Fatalf("write finding missing inferred label: %#v", writeFinding[0])
	}
	if !strings.Contains(writeFinding[0].Description, "inferred") || strings.Contains(writeFinding[0].Description, "PUT") {
		t.Fatalf("write description = %q", writeFinding[0].Description)
	}

	adminFinding := anonymousAccess{}.Evaluate(Input{
		Endpoint:    endpoint,
		Fingerprint: identity,
		Capabilities: capability.Result{Capabilities: []capability.Capability{
			{Name: capability.NameAnonymous, Availability: capability.AvailabilityAvailable},
			{Name: capability.NameSecurity, Availability: capability.AvailabilityUnsupported},
			{Name: capability.NameNodes, Availability: capability.AvailabilityAvailable},
		}},
	})
	if len(adminFinding) != 1 || adminFinding[0].Severity != model.SeverityCritical || !containsTag(adminFinding[0], "inferred") {
		t.Fatalf("admin inferred finding = %#v", adminFinding)
	}

	confirmed := anonymousAccess{}.Evaluate(Input{
		Endpoint:    endpoint,
		Fingerprint: identity,
		Capabilities: capability.Result{
			AnonymousSuperuser: true,
			Capabilities: []capability.Capability{
				{Name: capability.NameAnonymous, Availability: capability.AvailabilityAvailable},
				{Name: capability.NameSecurity, Availability: capability.AvailabilityAvailable},
			},
		},
	})
	if len(confirmed) != 1 || containsTag(confirmed[0], "inferred") || confirmed[0].Confidence != model.ConfidenceHigh {
		t.Fatalf("confirmed admin finding = %#v", confirmed)
	}
	if !containsEvidence(confirmed[0], "class_admin") || containsEvidence(confirmed[0], "class_admin_inferred") {
		t.Fatalf("confirmed admin evidence = %#v", confirmed[0].Evidence)
	}
}

func TestAnonymousFindingDoesNotCopyRoleNames(t *testing.T) {
	t.Parallel()

	findings := anonymousAccess{}.Evaluate(Input{
		Endpoint:    model.Endpoint{Scheme: model.SchemeHTTPS, Host: "192.168.1.10", Port: 9200},
		Fingerprint: confirmedIdentity(),
		Capabilities: capability.Result{
			AnonymousSuperuser: true,
			Capabilities: []capability.Capability{
				{Name: capability.NameAnonymous, Availability: capability.AvailabilityAvailable, Detail: canary},
				{Name: capability.NameSecurity, Availability: capability.AvailabilityAvailable, Detail: canary},
			},
		},
	})
	if len(findings) != 1 {
		t.Fatalf("findings = %#v", findings)
	}
	rendered := findings[0].Title + findings[0].Description + findings[0].Evidence[0].Summary
	for _, tag := range findings[0].Tags {
		rendered += tag
	}
	if strings.Contains(rendered, canary) {
		t.Fatalf("finding exposed canary: %+v", findings[0])
	}
}

func containsTag(finding model.Finding, tag string) bool {
	for _, item := range finding.Tags {
		if item == tag {
			return true
		}
	}
	return false
}

func containsEvidence(finding model.Finding, code string) bool {
	for _, item := range finding.Evidence {
		if item.Code == code {
			return true
		}
	}
	return false
}
