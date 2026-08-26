package audit

import (
	"strings"
	"testing"
)

func TestParseCredentialsSupportsBasicAndAPIKey(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	input := "# lab only\nbasic alice " + canary + "\napi_key id:" + canary + "\n"
	secrets, err := ParseCredentials(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseCredentials() error = %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("len = %d", len(secrets))
	}
	defer destroySecrets(secrets)
	if secrets[0].Kind() != "basic" || secrets[0].Username() != "alice" {
		t.Fatalf("basic secret kind/username = %q %q", secrets[0].Kind(), secrets[0].Username())
	}
	if secrets[1].Kind() != "api_key" || secrets[1].Username() != "" {
		t.Fatalf("api key secret = %#v", secrets[1])
	}
}

func TestParseCredentialsRejectsUnknownKindAndEmptyList(t *testing.T) {
	t.Parallel()

	if _, err := ParseCredentials(strings.NewReader("")); err == nil {
		t.Fatal("empty list succeeded")
	}
	if _, err := ParseCredentials(strings.NewReader("password credential-canary\n")); err == nil {
		t.Fatal("unknown kind succeeded")
	}
	if _, err := ParseCredentials(strings.NewReader("basic alice\n")); err == nil {
		t.Fatal("missing password succeeded")
	}
}

func TestParseCredentialsEnforcesListCeiling(t *testing.T) {
	t.Parallel()

	var builder strings.Builder
	for index := 0; index < maxCredentials+1; index++ {
		builder.WriteString("basic user password\n")
	}
	if _, err := ParseCredentials(strings.NewReader(builder.String())); err == nil {
		t.Fatal("oversized list succeeded")
	}
}
