package secrets

import "testing"

func BenchmarkCorrelateLargeDocument(b *testing.B) {
	accounts := make([]any, 64)
	for index := range accounts {
		accounts[index] = map[string]any{
			"username": "user",
			"password": "fake-password-garga-test-ONLY",
			"email":    "user@example.test",
			"meta":     "not-a-secret",
		}
	}
	document := map[string]any{
		"accounts": accounts,
		"config":   "DB_USER=admin\nDB_PASSWORD=fake-password-garga-test-ONLY\n",
		"nested": map[string]any{
			"database": map[string]any{
				"username": "admin",
				"password": "fake-password-garga-test-ONLY",
			},
		},
	}
	limits := walkLimits{
		maxDepth: 16, maxArrayItems: 256, maxObjectSize: 1024, maxFieldBytes: 1 << 20,
		entropyEnabled: true, broadCorrelation: true, scanGenericFields: true,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_ = walkDocument(document, limits)
	}
}

func BenchmarkCorrelateWideObject(b *testing.B) {
	object := map[string]any{}
	for index := 0; index < 200; index++ {
		object["field_"+string(rune('a'+(index%26)))+string(rune('0'+(index%10)))] = "value"
	}
	object["username"] = "admin"
	object["password"] = "fake-password-garga-test-ONLY"
	limits := walkLimits{maxDepth: 8, maxArrayItems: 64, maxObjectSize: 1024, maxFieldBytes: 4096, entropyEnabled: true}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_ = walkDocument(object, limits)
	}
}
