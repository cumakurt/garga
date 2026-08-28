package secrets

import (
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	privateKeyPreview   = "Private key detected"
	passwordHashPreview = "Password hash detected"
)

// Mask returns a console-safe preview of a secret. It never returns the full value
// for private keys.
func Mask(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if looksLikePrivateKey(value) {
		return privateKeyPreview
	}
	if kind := classifyPasswordHash(value); kind != "" {
		return passwordHashPreview + " (" + kind + ")"
	}
	if masked, ok := maskURL(value); ok {
		return masked
	}
	if masked, ok := maskBearer(value); ok {
		return masked
	}
	return maskGeneric(value)
}

func maskGeneric(value string) string {
	runes := []rune(value)
	length := len(runes)
	switch {
	case length <= 2:
		return strings.Repeat("*", length)
	case length <= 6:
		return string(runes[0]) + strings.Repeat("*", length-1)
	case isJWT(value) || looksLikeToken(value):
		prefixLen := 6
		if prefixLen > length/2 {
			prefixLen = 3
		}
		return string(runes[:prefixLen]) + "..." + string(runes[length-4:])
	case strings.HasPrefix(value, "AKIA") && length >= 8:
		return string(runes[:4]) + strings.Repeat("*", length-4)
	default:
		return string(runes[0]) + strings.Repeat("*", length-2) + string(runes[length-1])
	}
}

func maskBearer(value string) (string, bool) {
	lower := strings.ToLower(value)
	for _, prefix := range []string{"bearer ", "basic ", "apikey ", "api-key "} {
		if strings.HasPrefix(lower, prefix) {
			head := value[:len(prefix)]
			return head + maskGeneric(strings.TrimSpace(value[len(prefix):])), true
		}
	}
	return "", false
}

func maskURL(value string) (string, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}
	if parsed.User == nil {
		return "", false
	}
	username := parsed.User.Username()
	password, hasPassword := parsed.User.Password()
	if username == "" && !hasPassword {
		return "", false
	}
	maskedUser := maskShortIdentity(username)
	if hasPassword {
		parsed.User = url.UserPassword(maskedUser, maskGeneric(password))
	} else {
		parsed.User = url.User(maskedUser)
	}
	return parsed.String(), true
}

func maskShortIdentity(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return value
	}
	if len(runes) == 1 {
		return "*"
	}
	return string(runes[0]) + strings.Repeat("*", min(3, len(runes)-1))
}

func looksLikeToken(value string) bool {
	if len(value) < 16 {
		return false
	}
	if strings.ContainsAny(value, " \t\n") {
		return false
	}
	return strings.Contains(value, ".") || strings.Contains(value, "_") || strings.Contains(value, "-")
}

func truncateField(value string, maxBytes int) (string, bool) {
	if maxBytes <= 0 || len(value) <= maxBytes {
		return value, false
	}
	truncated := value[:maxBytes]
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated, true
}
