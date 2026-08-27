package model

import "testing"

func TestVersionConstraintSupports(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		constraint VersionConstraint
		version    string
		want       bool
	}{
		{"minimum", VersionConstraint{Min: "7.17.0"}, "7.17.0", true},
		{"maximum", VersionConstraint{Max: "9.4.4"}, "9.4.4", true},
		{"between", VersionConstraint{Min: "8.19.0", Max: "9.4.4"}, "9.3.8", true},
		{"below", VersionConstraint{Min: "8.19.0"}, "7.17.23", false},
		{"above", VersionConstraint{Max: "9.3.99"}, "9.4.0", false},
		{"prerelease", VersionConstraint{Min: "9.0.0"}, "9.4.0-SNAPSHOT", true},
		{"malformed", VersionConstraint{Min: "7.17.0"}, "unknown", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := test.constraint.Supports(test.version); got != test.want {
				t.Fatalf("Supports(%q) = %t, want %t", test.version, got, test.want)
			}
		})
	}
}

func TestVersionConstraintValidate(t *testing.T) {
	t.Parallel()
	if err := (VersionConstraint{Min: "9.0.0", Max: "8.19.0"}).Validate(); err == nil {
		t.Fatal("Validate() accepted a reversed range")
	}
}
