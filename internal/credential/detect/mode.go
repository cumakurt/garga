package detect

import (
	"fmt"
	"strings"
)

// Mode selects how candidate credentials are generated and tried.
type Mode string

const (
	// ModeStuffing tries explicit username+password pairs from a leak-style list.
	ModeStuffing Mode = "stuffing"
	// ModeSpraying tries each password across every username before the next password.
	ModeSpraying Mode = "spraying"
	// ModeBruteForce tries many passwords against one username.
	ModeBruteForce Mode = "brute-force"
	// ModeDictionary tries a bounded password wordlist against one username.
	ModeDictionary Mode = "dictionary"
)

// ParseMode normalizes and validates a detection mode name.
func ParseMode(value string) (Mode, error) {
	normalized := Mode(strings.ToLower(strings.TrimSpace(value)))
	switch normalized {
	case ModeStuffing, ModeSpraying, ModeBruteForce, ModeDictionary:
		return normalized, nil
	default:
		return "", fmt.Errorf("invalid credential detection mode %q: want stuffing, spraying, brute-force, or dictionary", value)
	}
}
