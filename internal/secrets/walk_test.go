package secrets

import "testing"

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
