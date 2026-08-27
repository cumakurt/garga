package logging

import (
	"log/slog"
	"strings"
)

var sensitiveKeys = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"credential":          {},
	"credentials":         {},
	"set-cookie":          {},
	"password":            {},
	"passwd":              {},
	"secret":              {},
	"token":               {},
	"api_key":             {},
	"apikey":              {},
	"www-authenticate":    {},
}

func compactSecrets(secrets []string) []string {
	filtered := make([]string, 0, len(secrets))
	seen := make(map[string]struct{}, len(secrets))
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if _, exists := seen[secret]; exists {
			continue
		}
		seen[secret] = struct{}{}
		filtered = append(filtered, secret)
	}
	return filtered
}

func redactAttr(attr slog.Attr, secrets []string) slog.Attr {
	attr.Value = attr.Value.Resolve()
	if attr.Value.Kind() == slog.KindGroup {
		group := attr.Value.Group()
		redactedGroup := make([]slog.Attr, len(group))
		for index, item := range group {
			redactedGroup[index] = redactAttr(item, secrets)
		}
		return slog.Attr{Key: attr.Key, Value: slog.GroupValue(redactedGroup...)}
	}
	if isSensitiveKey(attr.Key) {
		return slog.String(attr.Key, redacted)
	}
	if attr.Value.Kind() == slog.KindString {
		return slog.String(attr.Key, redactText(attr.Value.String(), secrets))
	}
	return attr
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.ReplaceAll(normalized, "_", "-")
	_, ok := sensitiveKeys[normalized]
	return ok
}

func redactText(value string, secrets []string) string {
	if value == "" {
		return value
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		value = strings.ReplaceAll(value, secret, redacted)
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "bearer ") || strings.Contains(lower, "basic ") || strings.Contains(lower, "apikey ") {
		return redacted
	}
	return value
}
