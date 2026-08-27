package redact

import (
	"reflect"
	"strings"
)

const replacement = "[REDACTED]"

var sensitiveFragments = []string{"password", "passwd", "authorization", "api_key", "apikey", "token", "secret", "credential", "cookie"}

// Value recursively redacts maps and slices before machine serialization.
func Value(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			if SensitiveKey(key) {
				result[key] = replacement
			} else {
				result[key] = Value(item)
			}
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = Value(item)
		}
		return result
	case string:
		return Text(typed)
	default:
		return reflectedValue(value)
	}
}

func reflectedValue(value any) any {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return nil
	}
	switch reflected.Kind() {
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return value
		}
		result := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			key := iterator.Key().String()
			if SensitiveKey(key) {
				result[key] = replacement
			} else {
				result[key] = Value(iterator.Value().Interface())
			}
		}
		return result
	case reflect.Slice, reflect.Array:
		result := make([]any, reflected.Len())
		for index := 0; index < reflected.Len(); index++ {
			result[index] = Value(reflected.Index(index).Interface())
		}
		return result
	default:
		return value
	}
}

func SensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	for _, fragment := range sensitiveFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

// Text removes terminal controls and masks values that look like authorization headers.
func Text(value string) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, value)
	lower := strings.ToLower(value)
	for _, prefix := range []string{"authorization:", "basic ", "bearer ", "apikey ", "api key "} {
		if strings.Contains(lower, prefix) {
			return replacement
		}
	}
	return value
}

func Evidence(evidence map[string]any) map[string]any {
	if evidence == nil {
		return nil
	}
	redacted, ok := Value(evidence).(map[string]any)
	if !ok {
		return nil
	}
	return redacted
}
