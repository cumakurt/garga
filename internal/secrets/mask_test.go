package secrets

import "testing"

func TestMaskPasswordKeepsFirstAndLast(t *testing.T) {
	t.Parallel()
	masked := Mask("password123")
	if masked == "password123" {
		t.Fatal("password was not masked")
	}
	if masked[0] != 'p' || masked[len(masked)-1] != '3' {
		t.Fatalf("masked password = %q", masked)
	}
	if containsFull("password123", masked) {
		t.Fatalf("masked value still contains the secret: %q", masked)
	}
}

func TestMaskAWSAccessKey(t *testing.T) {
	t.Parallel()
	const key = "AKIAIOSFODNN7EXAMPLE"
	masked := Mask(key)
	if masked == key || !hasPrefix(masked, "AKIA") {
		t.Fatalf("masked AWS key = %q", masked)
	}
}

func TestMaskConnectionString(t *testing.T) {
	t.Parallel()
	masked := Mask("postgres://admin:SuperSecret@db01/db")
	if masked == "postgres://admin:SuperSecret@db01/db" {
		t.Fatal("connection string was not masked")
	}
	if containsFull("SuperSecret", masked) || containsFull("admin:SuperSecret", masked) {
		t.Fatalf("connection string leaked secret: %q", masked)
	}
	if !containsFull("postgres://", masked) || !containsFull("@db01/db", masked) {
		t.Fatalf("connection string lost structure: %q", masked)
	}
}

func TestMaskPrivateKey(t *testing.T) {
	t.Parallel()
	masked := Mask("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0FAKE\n-----END RSA PRIVATE KEY-----")
	if masked != privateKeyPreview {
		t.Fatalf("private key mask = %q", masked)
	}
}

func TestMaskUTF8ShortString(t *testing.T) {
	t.Parallel()
	masked := Mask("ğü")
	if masked == "ğü" {
		t.Fatal("short UTF-8 string was not masked")
	}
}

func TestMaskBoundaryAndUnicodeValues(t *testing.T) {
	t.Parallel()
	values := []string{
		"", "x", "xy", "0** ", "***", "şifre", "TürkçeParola", "🔐", "🔐secret🙂",
		"Bearer GARGA_TEST_SECRET_7F4D91A2",
		"Basic R0FSR0FfVEVTVF9TRUNSRVRfN0Y0RDkxQTI=",
		"eyJhbGciOiJub25lIn0.eyJzdWIiOiJnYXJnYSJ9.GARGA_TEST_SIGNATURE",
	}
	for _, value := range values {
		masked := Mask(value)
		if value == "" {
			if masked != "" {
				t.Fatalf("Mask(empty) = %q", masked)
			}
			continue
		}
		if masked == value || containsFull(value, masked) {
			t.Fatalf("Mask(%q) leaked its input as %q", value, masked)
		}
	}
}

func containsFull(needle, haystack string) bool {
	return len(needle) > 0 && len(haystack) > 0 && (haystack == needle || (len(haystack) >= len(needle) && containsIndex(haystack, needle)))
}

func containsIndex(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func hasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}
