package credential

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestNewBasicAndAPIKey(t *testing.T) {
	t.Parallel()

	password := []byte("credential-canary")
	secret, err := NewBasic("alice", password)
	if err != nil {
		t.Fatalf("NewBasic() error = %v", err)
	}
	if string(password) == "credential-canary" {
		t.Fatal("NewBasic() did not clear the input password")
	}
	if secret.Kind() != KindBasic {
		t.Fatalf("kind = %q", secret.Kind())
	}
	header, err := secret.AuthorizationHeader()
	if err != nil || !strings.HasPrefix(header, "Basic ") {
		t.Fatalf("Authorization = %q, err = %v", header, err)
	}

	apiKey := []byte("id:credential-canary")
	key, err := NewAPIKey(apiKey)
	if err != nil {
		t.Fatalf("NewAPIKey() error = %v", err)
	}
	if string(apiKey) == "id:credential-canary" {
		t.Fatal("NewAPIKey() did not clear the input key")
	}
	header, err = key.AuthorizationHeader()
	if err != nil || !strings.HasPrefix(header, "ApiKey ") {
		t.Fatalf("API key Authorization = %q, err = %v", header, err)
	}
}

func TestSecretFormattingNeverLeaksMaterial(t *testing.T) {
	t.Parallel()

	const canary = "credential-canary"
	secret, err := NewBasic("alice", []byte(canary))
	if err != nil {
		t.Fatalf("NewBasic() error = %v", err)
	}
	payload, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	rendered := fmt.Sprintf("%s %#v %s", secret, secret, payload)
	if strings.Contains(rendered, canary) || strings.Contains(rendered, "alice") {
		t.Fatalf("secret formatting leaked identity: %s", rendered)
	}
	if secret.Username() != "alice" {
		t.Fatalf("Username() = %q", secret.Username())
	}
}

func TestNewSecretValidation(t *testing.T) {
	t.Parallel()

	if _, err := NewBasic("", []byte("secret")); err == nil {
		t.Fatal("NewBasic() accepted an empty username")
	}
	if _, err := NewBasic("user:name", []byte("secret")); err == nil {
		t.Fatal("NewBasic() accepted a colon in the username")
	}
	if _, err := NewBasic("alice", nil); err == nil {
		t.Fatal("NewBasic() accepted an empty password")
	}
	if _, err := NewAPIKey(nil); err == nil {
		t.Fatal("NewAPIKey() accepted an empty key")
	}
}

func TestDestroyPreventsReuse(t *testing.T) {
	t.Parallel()

	secret, err := NewBasic("alice", []byte("credential-canary"))
	if err != nil {
		t.Fatalf("NewBasic() error = %v", err)
	}
	secret.Destroy()
	if _, err := secret.AuthorizationHeader(); err == nil {
		t.Fatal("AuthorizationHeader() succeeded after Destroy()")
	}
}
