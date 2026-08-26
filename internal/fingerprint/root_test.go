package fingerprint

import "testing"

func TestValidVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  bool
	}{
		{"7.17.23", true},
		{"9.4.4-SNAPSHOT", true},
		{"9.4.4-rc.1", true},
		{"", false},
		{"9.4", false},
		{"v9.4.4", false},
		{"9.4.x", false},
		{"9.4.4-", false},
		{"9.4.4+credential", false},
		{"9.4.4-credential-canary", false},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()
			if got := validVersion(test.value); got != test.want {
				t.Fatalf("validVersion(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func TestParseRootRejectsMalformedOrAmbiguousJSON(t *testing.T) {
	t.Parallel()

	tests := [][]byte{
		nil,
		{},
		[]byte(`null`),
		[]byte(`[]`),
		[]byte(`{"version":{"number":"9.4.4"}`),
		[]byte(`{"version":{"number":"9.4.4"}} trailing`),
		[]byte(`{"version":{"number":944}}`),
		[]byte(`{"version":{"number":"9.4.4"}} {}`),
	}
	for _, body := range tests {
		info := parseRoot(body)
		if info.version != "" || info.hasName || info.isOpenSearch {
			t.Fatalf("parseRoot(%q) = %#v", body, info)
		}
	}
}

func TestReadSafeStringRejectsControlsAndOversizedValues(t *testing.T) {
	t.Parallel()

	if got := readSafeString([]byte(`"safe"`)); got != "safe" {
		t.Fatalf("readSafeString() = %q", got)
	}
	for _, raw := range [][]byte{
		[]byte(`123`),
		[]byte(`"line\nbreak"`),
		[]byte(`"` + string(make([]byte, maxRootStringBytes+1)) + `"`),
	} {
		if got := readSafeString(raw); got != "" {
			t.Fatalf("readSafeString(%q) = %q", raw, got)
		}
	}
}
