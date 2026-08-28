package secrets

import (
	"math"
	"strings"
	"unicode"
)

func shannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[rune]int, 16)
	total := 0
	for _, character := range value {
		counts[character]++
		total++
	}
	var entropy float64
	for _, count := range counts {
		probability := float64(count) / float64(total)
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func charsetDiversity(value string) int {
	var lower, upper, digit, other bool
	for _, character := range value {
		switch {
		case unicode.IsLower(character):
			lower = true
		case unicode.IsUpper(character):
			upper = true
		case unicode.IsDigit(character):
			digit = true
		default:
			other = true
		}
	}
	count := 0
	for _, present := range []bool{lower, upper, digit, other} {
		if present {
			count++
		}
	}
	return count
}

func looksLikeBase64(value string) bool {
	if len(value) < 16 || len(value)%4 != 0 {
		return false
	}
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '+' || character == '/' || character == '=' {
			continue
		}
		return false
	}
	return strings.Count(value, "=") <= 2
}

func looksLikeHex(value string) bool {
	if len(value) < 16 || len(value)%2 != 0 {
		return false
	}
	for _, character := range strings.ToLower(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func looksLikeUUID(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 36 {
		return compactUUID(value)
	}
	if value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func compactUUID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func highEntropySecret(value string) bool {
	length := len(value)
	if length < 20 {
		return false
	}
	entropy := shannonEntropy(value)
	diversity := charsetDiversity(value)
	switch {
	case looksLikeBase64(value) && entropy >= 4.5 && length >= 24:
		return true
	case looksLikeHex(value) && entropy >= 3.5 && length >= 32:
		return true
	case entropy >= 4.0 && diversity >= 3 && length >= 24:
		return true
	case entropy >= 3.7 && diversity >= 2 && length >= 32:
		return true
	default:
		return false
	}
}
