package detect

import (
	"strings"
	"testing"
)

func TestResolveCharsetNamedSets(t *testing.T) {
	t.Parallel()

	got, err := ResolveCharset("digits")
	if err != nil {
		t.Fatalf("ResolveCharset() error = %v", err)
	}
	if got != CharsetDigits {
		t.Fatalf("ResolveCharset(digits) = %q", got)
	}
}

func TestGeneratePasswordsBoundedOrder(t *testing.T) {
	t.Parallel()

	passwords, err := GeneratePasswords("ab", 1, 2)
	if err != nil {
		t.Fatalf("GeneratePasswords() error = %v", err)
	}
	want := []string{"a", "b", "aa", "ab", "ba", "bb"}
	if len(passwords) != len(want) {
		t.Fatalf("len(passwords) = %d, want %d", len(passwords), len(want))
	}
	for index, expected := range want {
		if string(passwords[index]) != expected {
			t.Fatalf("passwords[%d] = %q, want %q", index, passwords[index], expected)
		}
	}
}

func TestGeneratePasswordsRejectsOverflow(t *testing.T) {
	t.Parallel()

	_, err := GeneratePasswords("alnum", 1, 3)
	if err == nil {
		t.Fatal("GeneratePasswords() accepted an unbounded charset product")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v", err)
	}
}

func TestGeneratePasswordsRejectsInvalidLength(t *testing.T) {
	t.Parallel()

	if _, err := GeneratePasswords("ab", 2, 1); err == nil {
		t.Fatal("accepted min > max")
	}
	if _, err := GeneratePasswords("ab", 1, maxGenerateLength+1); err == nil {
		t.Fatal("accepted length above the ceiling")
	}
}
