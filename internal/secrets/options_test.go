package secrets

import "testing"

func TestParseConfidenceAndFormat(t *testing.T) {
	t.Parallel()
	confidence, err := ParseConfidence("confirmed-pattern")
	if err != nil || confidence != ConfidenceConfirmed {
		t.Fatalf("ParseConfidence = %q %v", confidence, err)
	}
	format, err := ParseFormat("jsonl")
	if err != nil || format != FormatJSONL {
		t.Fatalf("ParseFormat = %q %v", format, err)
	}
	if _, err := ParseFormat("csv"); err == nil {
		t.Fatal("csv must not be a secrets format")
	}
	if _, err := ParseFormat("console"); err == nil {
		t.Fatal("console must not be a secrets format")
	}
}

func TestOptionsRejectMultipleAuthMechanisms(t *testing.T) {
	t.Parallel()
	options := defaultOptions()
	options.PasswordEnv = "A"
	options.APIKeyEnv = "B"
	options.User = "garga"
	if err := options.validate(); err == nil {
		t.Fatal("expected multiple-mechanism error")
	}
}
