package redact

import "testing"

func TestValueRedactsSensitiveKeysAndAuthorizationText(t *testing.T) {
	t.Parallel()
	input := map[string]any{
		"password":      "credential-canary",
		"Authorization": "Basic abc",
		"nested":        map[string]any{"api_key": "secret-value", "status": "ok"},
		"note":          "authorization: Bearer token-canary",
	}
	redacted, ok := Value(input).(map[string]any)
	if !ok {
		t.Fatalf("Value() = %#v", Value(input))
	}
	if redacted["password"] != replacement || redacted["Authorization"] != replacement {
		t.Fatalf("top-level redaction = %#v", redacted)
	}
	nested, ok := redacted["nested"].(map[string]any)
	if !ok || nested["api_key"] != replacement || nested["status"] != "ok" {
		t.Fatalf("nested redaction = %#v", redacted["nested"])
	}
	if redacted["note"] != replacement {
		t.Fatalf("text redaction = %#v", redacted["note"])
	}
	if Evidence(map[string]any{"token": "x"})["token"] != replacement {
		t.Fatal("Evidence() did not redact token")
	}
}
