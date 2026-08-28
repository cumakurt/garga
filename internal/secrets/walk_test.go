package secrets

import (
	"context"
	"fmt"
	"testing"
)

func TestWalkNestedCredentialPair(t *testing.T) {
	t.Parallel()
	source := map[string]any{
		"services": []any{
			map[string]any{
				"username": "svc-garga",
				"password": "nested-fake-password-ONLY",
			},
		},
	}
	hits := walkDocument(source, walkLimits{maxDepth: 8, maxArrayItems: 16, maxObjectSize: 32, maxFieldBytes: 1024})
	var pair, password bool
	for _, item := range hits {
		if item.Detector == "credential-pair" {
			pair = true
		}
		if item.Category == "credential.password" {
			password = true
			if item.FieldPath != "services[0].password" {
				t.Fatalf("password path = %q", item.FieldPath)
			}
		}
	}
	if !pair || !password {
		t.Fatalf("nested pair detection failed: pair=%t password=%t hits=%v", pair, password, hitSummary(hits))
	}
}

func TestWalkRespectsDepthLimit(t *testing.T) {
	t.Parallel()
	source := map[string]any{
		"l1": map[string]any{
			"l2": map[string]any{
				"password": "fake-password-garga-test-ONLY",
			},
		},
	}
	hits := walkDocument(source, walkLimits{maxDepth: 1, maxArrayItems: 8, maxObjectSize: 32, maxFieldBytes: 1024})
	for _, item := range hits {
		if item.Category == "credential.password" {
			t.Fatalf("depth limit leaked nested password: %+v", item)
		}
	}
}

func TestSourceIncludesPrioritizesSensitiveFields(t *testing.T) {
	t.Parallel()
	fields := []FieldSemantics{
		AnalyzeField("message"),
		AnalyzeField("password"),
		AnalyzeField("count"),
	}
	includes := sourceIncludes(fields, 8, false)
	if len(includes) == 0 || includes[0] != "password" {
		t.Fatalf("includes = %v", includes)
	}
}

func TestWalkPrefersSensitiveFieldsWhenObjectExceedsCap(t *testing.T) {
	t.Parallel()
	source := map[string]any{
		"password": "fake-password-garga-test-ONLY",
	}
	for index := 0; index < 80; index++ {
		source[fmt.Sprintf("aaa_%03d", index)] = "not-a-secret"
	}
	hits := walkDocument(source, walkLimits{
		maxDepth: 4, maxArrayItems: 4, maxObjectSize: 8, maxFieldBytes: 1024, entropyEnabled: true,
	})
	found := false
	for _, item := range hits {
		if item.Category == "credential.password" && item.FieldPath == "password" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("wide object dropped the sensitive field: %v", hitSummary(hits))
	}
}

func TestWalkSkipsEntropyWhenDisabled(t *testing.T) {
	t.Parallel()
	source := map[string]any{
		"encryption_key": "s9f8a7d6s5f4a3d2s1f0a9d8s7f6a5d4s3f2garga",
	}
	limits := walkLimits{maxDepth: 4, maxArrayItems: 4, maxObjectSize: 16, maxFieldBytes: 1024}
	disabled := walkDocument(source, limits)
	for _, item := range disabled {
		if item.Detector == "entropy" {
			t.Fatalf("entropy hit retained while disabled: %+v", item)
		}
	}
	limits.entropyEnabled = true
	enabled := walkDocument(source, limits)
	found := false
	for _, item := range enabled {
		if item.Detector == "entropy" {
			found = true
		}
	}
	if !found {
		t.Fatal("enabled entropy walk produced no entropy hit")
	}
}

func TestWalkDocumentBoundsRetainedHits(t *testing.T) {
	t.Parallel()
	source := map[string]any{
		"password":      "first-secret-value",
		"client_secret": "second-secret-value",
		"api_key":       "third-secret-value",
		"token":         "fourth-secret-value",
	}
	hits := walkDocument(source, walkLimits{
		maxDepth: 8, maxArrayItems: 8, maxObjectSize: 32, maxFieldBytes: 1024, maxHits: 3,
	})
	if len(hits) != 3 {
		t.Fatalf("retained hits = %d, want hard limit 3", len(hits))
	}
}

func TestMappingFieldsCapsNestedPropertiesWrappers(t *testing.T) {
	t.Parallel()
	current := any(map[string]any{"password": map[string]any{"type": "keyword"}})
	for index := 0; index < 64; index++ {
		current = map[string]any{"properties": current}
	}
	fields := mappingFields(current, "", 0, walkLimits{maxDepth: 8, maxObjectSize: 32})
	if len(fields) != 0 {
		t.Fatalf("deep properties wrappers leaked %d fields", len(fields))
	}
	shallow := mappingFields(map[string]any{"properties": map[string]any{"password": map[string]any{"type": "keyword"}}}, "", 0, walkLimits{maxDepth: 8, maxObjectSize: 32})
	if len(shallow) != 1 || shallow[0].Path != "password" {
		t.Fatalf("standard mapping fields = %+v", shallow)
	}
}

func TestWalkStopsOnCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source := map[string]any{}
	for index := 0; index < 256; index++ {
		source[fmt.Sprintf("password_%03d", index)] = "fake-password-garga-test-ONLY"
	}
	hits := walkDocument(source, walkLimits{
		ctx: ctx, maxDepth: 8, maxArrayItems: 64, maxObjectSize: 10000, maxFieldBytes: 1024,
	})
	if len(hits) != 0 {
		t.Fatalf("canceled walk produced %d hits", len(hits))
	}
}
