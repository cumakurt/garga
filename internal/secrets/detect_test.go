package secrets

import (
	"strings"
	"testing"
)

func TestDetectKnownSecrets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		field    string
		value    string
		category string
		detector string
	}{
		{"aws_access_key_id", "AKIAIOSFODNN7EXAMPLE", "credential.cloud.aws", "aws-access-key"},
		{"token", "ghp_000000000000000000000000000000000000", "credential.github", "github-pat"},
		{"gitlab", "glpat-" + strings.Repeat("a", 20), "credential.gitlab", "gitlab-pat"},
		{"jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJnYXJnYS10ZXN0IiwiZGF0YXNldCI6InRlc3QifQ.gargaTestSig", "credential.jwt", "jwt"},
		{"private_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----", "credential.private_key", "pem-private-key"},
		{"dsn", "postgres://garga_test:FakePasswordOnly@localhost:5432/garga_test", "credential.connection_string", "postgres-url"},
		{"client_secret", "garga-test-oauth-secret-NOT-REAL-0123456789", "credential.oauth", "entropy"},
	}
	for _, test := range cases {
		hits := detectValue(test.value, AnalyzeField(test.field), DefaultMaxFieldBytes)
		if !hasHit(hits, test.detector, test.category) {
			t.Fatalf("field %s value %q detectors=%v", test.field, test.value, hitSummary(hits))
		}
	}
}

func TestDetectPasswordHashRequiresContext(t *testing.T) {
	t.Parallel()
	hash := "$2a$10$gargaTestFakeBcryptHashValueNotARealPasswordHashXX"
	if hits := detectValue(hash, AnalyzeField("password_hash"), DefaultMaxFieldBytes); !hasHit(hits, "password-hash", "credential.password_hash") {
		t.Fatalf("password_hash missed bcrypt: %v", hitSummary(hits))
	}
	if hits := detectValue(hash, AnalyzeField("request_id"), DefaultMaxFieldBytes); hasHit(hits, "password-hash", "credential.password_hash") {
		t.Fatal("bcrypt-like value on request_id must not be reported as a password hash")
	}
}

func TestDetectFalsePositives(t *testing.T) {
	t.Parallel()
	cases := []struct {
		field string
		value string
	}{
		{"request_id", "550e8400-e29b-41d4-a716-446655440000"},
		{"checksum", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"id", "a1b2c3d4e5f6789012345678abcdef01"},
		{"animal", "monkey"},
		{"certificate", "-----BEGIN CERTIFICATE-----\nMIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBX\n-----END CERTIFICATE-----"},
		{"public_key", "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMFAKE\n-----END PUBLIC KEY-----"},
	}
	for _, test := range cases {
		hits := detectValue(test.value, AnalyzeField(test.field), DefaultMaxFieldBytes)
		for _, item := range hits {
			if item.Severity == SeverityCritical || item.Severity == SeverityHigh {
				t.Fatalf("%s=%q produced high-severity hit %+v", test.field, test.value, item)
			}
			if item.Category != "material.public" && confidenceRank(item.Confidence) >= confidenceRank(ConfidenceHigh) && item.Detector != "public-material" {
				t.Fatalf("%s=%q produced high-confidence hit %+v", test.field, test.value, item)
			}
		}
	}
}

func TestGenericEntropyUsesFieldContext(t *testing.T) {
	t.Parallel()
	secret := "s9f8a7d6s5f4a3d2s1f0a9d8s7f6a5d4s3f2"
	high := detectValue(secret, AnalyzeField("client_secret"), DefaultMaxFieldBytes)
	if !hasDetector(high, "sensitive-field") && !hasDetector(high, "entropy") {
		t.Fatalf("client_secret high-entropy missed: %v", hitSummary(high))
	}
	low := detectValue(secret, AnalyzeField("request_id"), DefaultMaxFieldBytes)
	for _, item := range low {
		if item.Severity == SeverityCritical {
			t.Fatalf("request_id entropy was critical: %+v", item)
		}
	}
}

func hasHit(hits []hit, detector, category string) bool {
	for _, item := range hits {
		if item.Detector == detector && (category == "" || item.Category == category) {
			return true
		}
	}
	return false
}

func hasDetector(hits []hit, detector string) bool {
	return hasHit(hits, detector, "")
}

func hitSummary(hits []hit) []string {
	out := make([]string, 0, len(hits))
	for _, item := range hits {
		out = append(out, item.Detector+":"+item.Category)
	}
	return out
}
