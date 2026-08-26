package credential

import (
	"errors"
	"strings"
	"testing"
)

func TestRedactRemovesPasswordAndHeader(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	secret, err := NewBasic("alice", []byte(canary))
	if err != nil {
		t.Fatalf("NewBasic() error = %v", err)
	}
	header, err := secret.AuthorizationHeader()
	if err != nil {
		t.Fatalf("AuthorizationHeader() error = %v", err)
	}
	text := "password=" + canary + " header=" + header
	got := Redact(text, secret)
	if strings.Contains(got, canary) || strings.Contains(got, header) {
		t.Fatalf("Redact() = %q", got)
	}
	if !strings.Contains(got, redacted) {
		t.Fatalf("Redact() missing marker: %q", got)
	}
}

func TestRedactErrorUnwrapsCause(t *testing.T) {
	t.Parallel()

	secret, err := NewAPIKey([]byte("credential-canary"))
	if err != nil {
		t.Fatalf("NewAPIKey() error = %v", err)
	}
	cause := errors.New("transport failed: credential-canary")
	got := redactError(cause, secret)
	if strings.Contains(got.Error(), "credential-canary") {
		t.Fatalf("redactError() = %q", got)
	}
	if !errors.Is(got, cause) {
		t.Fatalf("redactError() lost cause: %v", got)
	}
}
