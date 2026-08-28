package secrets

import "testing"

func TestAnalyzeFieldScoresSensitiveNames(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		severity Severity
		category string
	}{
		{"password", SeverityCritical, "credential.password"},
		{"dbPassword", SeverityCritical, "credential.password"},
		{"db_password", SeverityCritical, "credential.password"},
		{"db-password", SeverityCritical, "credential.password"},
		{"config.database.password", SeverityCritical, "credential.password"},
		{"client_secret", SeverityCritical, "credential.oauth"},
		{"apiKey", SeverityCritical, "credential.api_key"},
		{"private_key", SeverityCritical, "credential.private_key"},
		{"access_token", SeverityHigh, "credential.access_token"},
		{"authorization", SeverityHigh, "credential.authorization"},
		{"username", SeverityMedium, "identity.username"},
		{"email", SeverityLow, "identity.email"},
	}
	for _, test := range cases {
		semantics := AnalyzeField(test.name)
		if !semantics.Sensitive || semantics.Severity != test.severity || semantics.Category != test.category {
			t.Fatalf("AnalyzeField(%q) = sensitive=%t severity=%s category=%s", test.name, semantics.Sensitive, semantics.Severity, semantics.Category)
		}
	}
}

func TestAnalyzeFieldDoesNotMatchKeyInsideMonkey(t *testing.T) {
	t.Parallel()
	semantics := AnalyzeField("monkey")
	if semantics.Sensitive {
		t.Fatalf("monkey must not be treated as a secret field: %+v", semantics)
	}
}

func TestAnalyzeFieldMarksIDLikeAndTextLike(t *testing.T) {
	t.Parallel()
	if !AnalyzeField("request_id").IDLike {
		t.Fatal("request_id should be id-like")
	}
	if !AnalyzeField("message").TextLike {
		t.Fatal("message should be text-like")
	}
	if AnalyzeField("password_hash").IDLike {
		t.Fatal("password_hash must not be treated as a generic id/hash field")
	}
}
