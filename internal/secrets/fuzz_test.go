package secrets

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzAnalyzeField(f *testing.F) {
	for _, seed := range []string{"password", "clientSecret", "accounts[0].api_key", "monkey", "çalışan_şifresi", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, path string) {
		semantics := AnalyzeField(path)
		if semantics.Path != path {
			t.Fatalf("path changed: got %q, want %q", semantics.Path, path)
		}
		for _, token := range semantics.Tokens {
			if token == "" || token != strings.ToLower(token) {
				t.Fatalf("invalid normalized token %q for %q", token, path)
			}
		}
	})
}

func FuzzMask(f *testing.F) {
	for _, seed := range []string{
		"GARGA_TEST_SECRET_7F4D91A2",
		"ğü",
		"Bearer abcdefghijklmnopqrstuvwxyz",
		"postgres://admin:password@localhost/database",
		"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
		"0** ",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		masked := Mask(value)
		if !utf8.ValidString(masked) {
			t.Fatalf("Mask returned invalid UTF-8 for %q", value)
		}
		trimmed := strings.TrimSpace(value)
		if trimmed != "" && strings.Trim(trimmed, "*") != "" && masked == trimmed {
			t.Fatalf("Mask returned plaintext input %q", value)
		}
	})
}
