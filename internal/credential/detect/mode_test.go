package detect

import (
	"testing"
)

func TestParseMode(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  Mode
	}{
		{"stuffing", ModeStuffing},
		{"SPRAYING", ModeSpraying},
		{"brute-force", ModeBruteForce},
		{"dictionary", ModeDictionary},
	}
	for _, testCase := range cases {
		got, err := ParseMode(testCase.input)
		if err != nil {
			t.Fatalf("ParseMode(%q) error = %v", testCase.input, err)
		}
		if got != testCase.want {
			t.Fatalf("ParseMode(%q) = %q, want %q", testCase.input, got, testCase.want)
		}
	}
}

func TestParseModeRejectsUnknown(t *testing.T) {
	t.Parallel()

	if _, err := ParseMode("rainbow"); err == nil {
		t.Fatal("ParseMode() succeeded for unknown mode")
	}
}
