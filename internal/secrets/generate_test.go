package secrets

import (
	"strings"
	"testing"
)

func TestSyntheticDocumentsCoverDetectors(t *testing.T) {
	t.Parallel()
	limits := walkLimits{
		maxDepth:      DefaultMaxDepth,
		maxArrayItems: DefaultMaxArrayItems,
		maxObjectSize: DefaultMaxObjectSize,
		maxFieldBytes: DefaultMaxFieldBytes,
	}
	seen := map[string]int{}
	for _, document := range SyntheticDocuments() {
		for _, item := range walkDocument(document.Source, limits) {
			seen[item.Detector]++
		}
	}
	required := []string{
		"aws-access-key",
		"aws-secret-access-key",
		"aws-session-token",
		"google-api-key",
		"azure-storage-key",
		"azure-client-secret",
		"github-pat",
		"github-fine-grained-pat",
		"gitlab-pat",
		"slack-token",
		"slack-webhook",
		"jwt",
		"pem-private-key",
		"pgp-private-key",
		"postgres-url",
		"mysql-url",
		"mongodb-url",
		"redis-url",
		"mssql-url",
		"elasticsearch-url",
		"jdbc-url",
		"kubernetes-sa-token",
		"docker-auth",
		"password-hash",
		"authorization-header",
		"env-assignment",
		"ldap-bind",
		"smtp-credential",
		"credential-pair",
		"sensitive-field",
		"entropy",
	}
	var missing []string
	for _, detector := range required {
		if seen[detector] == 0 {
			missing = append(missing, detector)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("synthetic corpus missing detectors %v; seen=%v", missing, seen)
	}
}

func TestFalsePositiveDocumentsStayLowRisk(t *testing.T) {
	t.Parallel()
	limits := walkLimits{
		maxDepth:      DefaultMaxDepth,
		maxArrayItems: DefaultMaxArrayItems,
		maxObjectSize: DefaultMaxObjectSize,
		maxFieldBytes: DefaultMaxFieldBytes,
	}
	for _, document := range FalsePositiveDocuments() {
		for _, item := range walkDocument(document.Source, limits) {
			if item.Severity == SeverityCritical || item.Severity == SeverityHigh {
				t.Fatalf("%s produced high-severity hit %+v", document.ID, item)
			}
			if item.Category != "material.public" && confidenceRank(item.Confidence) >= confidenceRank(ConfidenceHigh) && item.Detector != "public-material" {
				t.Fatalf("%s produced high-confidence hit %+v", document.ID, item)
			}
		}
	}
}

func TestGoogleAPIKeyLength(t *testing.T) {
	t.Parallel()
	key := "AIza" + "SyDl" + strings.Repeat("A", 31)
	if rest := strings.TrimPrefix(key, "AIza"); len(rest) != 35 {
		t.Fatalf("google api key suffix length = %d, want 35", len(rest))
	}
}
