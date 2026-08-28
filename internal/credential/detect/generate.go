package detect

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	CharsetDigits = "0123456789"
	CharsetLower  = "abcdefghijklmnopqrstuvwxyz"
	CharsetUpper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	CharsetAlnum  = CharsetLower + CharsetUpper + CharsetDigits

	maxCharsetRunes   = 128
	maxGenerateLength = 4
)

// ResolveCharset expands a named set (digits, lower, upper, alnum) or a custom alphabet.
func ResolveCharset(value string) (string, error) {
	normalized := strings.TrimSpace(value)
	switch strings.ToLower(normalized) {
	case "digits":
		return CharsetDigits, nil
	case "lower":
		return CharsetLower, nil
	case "upper":
		return CharsetUpper, nil
	case "alnum":
		return CharsetAlnum, nil
	default:
		return uniqueCharset(normalized)
	}
}

// GeneratePasswords materializes a bounded brute-force candidate list.
//
// The cartesian product is rejected unless the total is at most maxPasswords.
func GeneratePasswords(charset string, minLength, maxLength int) ([][]byte, error) {
	resolved, err := ResolveCharset(charset)
	if err != nil {
		return nil, fmt.Errorf("generate passwords: %w", err)
	}
	if minLength < 1 || maxLength < minLength || maxLength > maxGenerateLength {
		return nil, fmt.Errorf("generate passwords: length must be between 1 and %d, and min must not exceed max", maxGenerateLength)
	}
	alphabet := []rune(resolved)
	total, ok := candidateCount(len(alphabet), minLength, maxLength)
	if !ok || total > maxPasswords {
		return nil, fmt.Errorf("generate passwords: candidate count exceeds %d; narrow charset or max length", maxPasswords)
	}
	passwords := make([][]byte, 0, total)
	for length := minLength; length <= maxLength; length++ {
		generated := generateLength(alphabet, length)
		passwords = append(passwords, generated...)
	}
	return passwords, nil
}

func uniqueCharset(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("charset is required")
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("charset is not valid UTF-8")
	}
	seen := make(map[rune]struct{}, len(value))
	runes := make([]rune, 0, len(value))
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", fmt.Errorf("charset contains an invalid character")
		}
		if _, exists := seen[character]; exists {
			continue
		}
		seen[character] = struct{}{}
		runes = append(runes, character)
		if len(runes) > maxCharsetRunes {
			return "", fmt.Errorf("charset exceeds %d unique characters", maxCharsetRunes)
		}
	}
	if len(runes) == 0 {
		return "", fmt.Errorf("charset is required")
	}
	return string(runes), nil
}

func candidateCount(base, minLength, maxLength int) (int, bool) {
	if base <= 0 {
		return 0, false
	}
	total := 0
	for length := minLength; length <= maxLength; length++ {
		count := 1
		for index := 0; index < length; index++ {
			if count > maxPasswords/base {
				return 0, false
			}
			count *= base
		}
		if total > maxPasswords-count {
			return 0, false
		}
		total += count
	}
	return total, true
}

func generateLength(alphabet []rune, length int) [][]byte {
	if length < 1 {
		return nil
	}
	total := 1
	for index := 0; index < length; index++ {
		total *= len(alphabet)
	}
	out := make([][]byte, 0, total)
	indexes := make([]int, length)
	for {
		var builder strings.Builder
		builder.Grow(length)
		for _, index := range indexes {
			builder.WriteRune(alphabet[index])
		}
		out = append(out, []byte(builder.String()))

		position := length - 1
		for position >= 0 {
			indexes[position]++
			if indexes[position] < len(alphabet) {
				break
			}
			indexes[position] = 0
			position--
		}
		if position < 0 {
			break
		}
	}
	return out
}
