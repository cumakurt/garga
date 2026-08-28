package secrets

import (
	"strings"
	"testing"
)

func TestNormalizeFieldName(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"clientSecret":    "client secret",
		"db_password":     "db password",
		"client-secret":   "client secret",
		"aws.accessKeyId": "aws access key id",
		"access_key":      "access key",
	}
	for input, want := range cases {
		if got := NormalizeFieldName(input); got != want {
			t.Fatalf("NormalizeFieldName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCorrelateUsernamePassword(t *testing.T) {
	t.Parallel()
	hits := walkDocument(map[string]any{
		"username": "admin",
		"password": "fake-test-password",
	}, testLimits())
	assertPair(t, hits, "username_password", "credential.pair", []string{"username", "password"})
}

func TestCorrelateClientCredentials(t *testing.T) {
	t.Parallel()
	hits := walkDocument(map[string]any{
		"client_id":     "test",
		"client_secret": "fake-secret-value",
	}, testLimits())
	assertPair(t, hits, "client_credentials", "credential.client", []string{"client_id", "client_secret"})
}

func TestCorrelateAccessKeyPair(t *testing.T) {
	t.Parallel()
	hits := walkDocument(map[string]any{
		"access_key": "fake-access-key-value",
		"secret_key": "fake-secret-key-value",
	}, testLimits())
	assertPair(t, hits, "access_key_pair", "credential.access_key_pair", []string{"access_key", "secret_key"})
}

func TestCorrelateNestedDatabaseObject(t *testing.T) {
	t.Parallel()
	hits := walkDocument(map[string]any{
		"database": map[string]any{
			"username": "admin",
			"password": "fake-test-password",
		},
	}, testLimits())
	assertPair(t, hits, "username_password", "credential.pair", []string{"database.username", "database.password"})
	for _, item := range hits {
		if item.Detector == "credential-pair" && item.ObjectPath != "database" {
			t.Fatalf("object_path = %q", item.ObjectPath)
		}
	}
}

func TestCorrelateArrayItemsSeparately(t *testing.T) {
	t.Parallel()
	hits := walkDocument(map[string]any{
		"accounts": []any{
			map[string]any{"username": "user1", "password": "fake-password-one"},
			map[string]any{"username": "user2", "password": "fake-password-two"},
		},
	}, testLimits())
	var pairs []hit
	for _, item := range hits {
		if item.Detector == "credential-pair" {
			pairs = append(pairs, item)
		}
	}
	if len(pairs) != 2 {
		t.Fatalf("pairs = %d hits=%v", len(pairs), hitSummary(hits))
	}
	seen := map[string]bool{}
	for _, item := range pairs {
		seen[strings.Join(item.RelatedFields, ",")] = true
	}
	if !seen["accounts[0].username,accounts[0].password"] || !seen["accounts[1].username,accounts[1].password"] {
		t.Fatalf("related fields = %#v", seen)
	}
}

func TestCorrelateDoesNotCrossArrayElements(t *testing.T) {
	t.Parallel()
	hits := walkDocument(map[string]any{
		"accounts": []any{
			map[string]any{"username": "user1"},
			map[string]any{"password": "fake-password-two"},
		},
	}, testLimits())
	for _, item := range hits {
		if item.Detector == "credential-pair" {
			t.Fatalf("cross-element pair: %+v", item)
		}
	}
}

func TestCorrelateDoesNotCrossSiblingObjects(t *testing.T) {
	t.Parallel()
	hits := walkDocument(map[string]any{
		"user":     map[string]any{"username": "admin"},
		"database": map[string]any{"password": "fake-test-password"},
	}, testLimits())
	for _, item := range hits {
		if item.Detector == "credential-pair" {
			t.Fatalf("cross-object pair: %+v", item)
		}
	}
}

func TestCorrelateIgnoresRequestID(t *testing.T) {
	t.Parallel()
	hits := walkDocument(map[string]any{
		"request_id": "s9f8a7d6s5f4a3d2s1f0a9d8s7f6a5d4s3f2",
		"trace":      "s9f8a7d6s5f4a3d2s1f0a9d8s7f6a5d4s3f2",
	}, testLimits())
	for _, item := range hits {
		if item.Detector == "credential-pair" {
			t.Fatalf("request_id correlated: %+v", item)
		}
	}
}

func TestCorrelateIgnoresPublicKeyWithUsername(t *testing.T) {
	t.Parallel()
	hits := walkDocument(map[string]any{
		"username":   "admin",
		"public_key": "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMFAKE\n-----END PUBLIC KEY-----",
	}, testLimits())
	for _, item := range hits {
		if item.Detector == "credential-pair" {
			t.Fatalf("public_key correlated: %+v", item)
		}
	}
}

func TestCorrelateConnectionString(t *testing.T) {
	t.Parallel()
	hits := detectValue("postgres://admin:fake-test-password@db01/prod", AnalyzeField("dsn"), DefaultMaxFieldBytes)
	var found bool
	for _, item := range hits {
		if item.Category == "credential.connection_string" && item.CredentialType == "connection_string" {
			found = true
			if item.MaskedValues["password"] == "fake-test-password" || strings.Contains(item.Masked, "fake-test-password") {
				t.Fatalf("connection string leaked password: %+v", item)
			}
			if item.MaskedValues["username"] == "" || item.MaskedValues["host"] == "" {
				t.Fatalf("missing connection components: %+v", item)
			}
		}
	}
	if !found {
		t.Fatalf("connection string correlation missing: %v", hitSummary(hits))
	}
}

func TestCorrelateConfigBlock(t *testing.T) {
	t.Parallel()
	hits := walkDocument(map[string]any{
		"config": "DB_USER=admin\nDB_PASSWORD=fake-test-password\n",
	}, testLimits())
	assertPair(t, hits, "database_credentials", "credential.database", []string{"config.DB_USER", "config.DB_PASSWORD"})
}

func TestCorrelateDoesNotKeepPlaintext(t *testing.T) {
	t.Parallel()
	secret := "fake-test-password"
	hits := walkDocument(map[string]any{"username": "admin", "password": secret}, testLimits())
	for _, item := range hits {
		if item.Detector == "credential-pair" {
			if item.Raw != "" {
				t.Fatal("correlation stored plaintext secret")
			}
			if strings.Contains(item.Masked, secret) {
				t.Fatalf("masked preview leaked secret: %q", item.Masked)
			}
			for _, value := range item.MaskedValues {
				if value == secret {
					t.Fatal("masked values leaked secret")
				}
			}
		}
	}
}

func TestDeepScanAliasesEnableBroaderCorrelation(t *testing.T) {
	t.Parallel()
	source := map[string]any{
		"uid":         "operator",
		"secretValue": "fake-deep-secret-value",
	}
	normal := walkDocument(source, testLimits())
	for _, item := range normal {
		if item.Detector == "credential-pair" {
			t.Fatalf("normal scan correlated deep aliases: %+v", item)
		}
	}
	deep := walkDocument(source, deepLimits())
	assertPair(t, deep, "username_password", "credential.pair", []string{"uid", "secretValue"})
}

func testLimits() walkLimits {
	return walkLimits{maxDepth: 8, maxArrayItems: 16, maxObjectSize: 32, maxFieldBytes: 1024, entropyEnabled: true}
}

func deepLimits() walkLimits {
	limits := testLimits()
	limits.broadCorrelation = true
	limits.scanGenericFields = true
	return limits
}

func assertPair(t *testing.T, hits []hit, credentialType, category string, related []string) {
	t.Helper()
	for _, item := range hits {
		if item.Detector != "credential-pair" {
			continue
		}
		if item.CredentialType != credentialType || item.Category != category {
			continue
		}
		if len(item.RelatedFields) != len(related) {
			continue
		}
		match := true
		for index, path := range related {
			if item.RelatedFields[index] != path {
				match = false
				break
			}
		}
		if match {
			if item.Severity != SeverityCritical && item.Severity != SeverityHigh {
				t.Fatalf("pair severity = %s", item.Severity)
			}
			return
		}
	}
	t.Fatalf("missing %s pair related=%v hits=%v", credentialType, related, hitSummary(hits))
}

func TestParseAssignmentFieldsCapsLineCount(t *testing.T) {
	t.Parallel()
	value := strings.Repeat("password=fake-password-ONLY\n", 20000)
	fields := parseAssignmentFields(value, "message")
	if len(fields) != maxAssignmentFields {
		t.Fatalf("assignment fields = %d, want cap %d", len(fields), maxAssignmentFields)
	}
}
