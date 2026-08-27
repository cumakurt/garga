package capability

import "testing"

func TestJoinAPIPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		base string
		api  string
		want string
	}{
		{"", pathHealth, pathHealth},
		{"/", pathHealth, pathHealth},
		{"/elastic", pathHealth, "/elastic/_cluster/health"},
		{"/elastic/", pathState, "/elastic/_cluster/state/version"},
		{"/es", pathNodes, "/es/_nodes/_local/http"},
		{"/es/", pathCat, "/es/_cat/health"},
		{"/es", pathIndices, "/es/_cat/indices"},
		{"/proxy", PathAuthenticate, "/proxy/_security/_authenticate"},
	}
	for _, test := range tests {
		got, err := joinAPIPath(test.base, test.api)
		if err != nil {
			t.Fatalf("joinAPIPath(%q, %q) error = %v", test.base, test.api, err)
		}
		if got != test.want {
			t.Fatalf("joinAPIPath(%q, %q) = %q, want %q", test.base, test.api, got, test.want)
		}
	}
}

func TestJoinAPIPathRejectsNonAllowlistedAndUnsafeInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		base string
		api  string
	}{
		{"", "/_cluster/health?pretty=true"},
		{"", "/_all"},
		{"", "/_cluster/settings"},
		{"", "/_security/user"},
		{"", "/_security/user/_authenticate"},
		{"elastic", pathHealth},
		{"/elastic?x=1", pathHealth},
		{"", "/../_cluster/health"},
		{"", "/_cluster/health#frag"},
	}
	for _, test := range tests {
		if _, err := joinAPIPath(test.base, test.api); err == nil {
			t.Fatalf("joinAPIPath(%q, %q) returned nil error", test.base, test.api)
		}
	}
}

func TestCatalogPathsAreAllowlistedGETTargets(t *testing.T) {
	t.Parallel()

	if len(extraProbes) != 6 {
		t.Fatalf("extraProbes = %d, want 6", len(extraProbes))
	}
	seen := map[Name]struct{}{}
	for _, spec := range extraProbes {
		if _, exists := seen[spec.name]; exists {
			t.Fatalf("duplicate probe name %q", spec.name)
		}
		seen[spec.name] = struct{}{}
		if _, err := joinAPIPath("", spec.path); err != nil {
			t.Fatalf("catalog path %q is not allowlisted: %v", spec.path, err)
		}
		if spec.path[0] != '/' {
			t.Fatalf("catalog path %q is not absolute", spec.path)
		}
	}
}

func TestReadOnlyProbe(t *testing.T) {
	t.Parallel()

	method, path, ok := ReadOnlyProbe(NameIndices)
	if !ok || method != "GET" || path != pathIndices {
		t.Fatalf("ReadOnlyProbe(indices) = %q %q %t", method, path, ok)
	}
	if _, _, ok := ReadOnlyProbe(NameAnonymous); ok {
		t.Fatal("derived capability unexpectedly has a catalog probe")
	}
}

func TestAllowlistIsDerivedFromCatalog(t *testing.T) {
	t.Parallel()

	paths := AllowlistedAPIPaths()
	if len(paths) != len(extraProbes) {
		t.Fatalf("AllowlistedAPIPaths() = %d, want %d", len(paths), len(extraProbes))
	}
	for index, spec := range extraProbes {
		if paths[index] != spec.path {
			t.Fatalf("AllowlistedAPIPaths()[%d] = %q, want %q", index, paths[index], spec.path)
		}
		if !IsAllowlistedAPIPath(spec.path) {
			t.Fatalf("catalog path %q is not allowlisted", spec.path)
		}
	}
	if !IsAllowlistedAPIPath(PathAuthenticate) {
		t.Fatal("PathAuthenticate is missing from the GET catalog")
	}
	if IsAllowlistedAPIPath("/_security/user/_authenticate") {
		t.Fatal("Get User path must not be allowlisted")
	}
}
