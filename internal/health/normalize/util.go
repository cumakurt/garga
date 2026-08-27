package normalize

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

func decodeObject(body []byte) map[string]any {
	if len(body) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var object map[string]any
	if decoder.Decode(&object) != nil {
		return nil
	}
	return object
}

func decodeArray(body []byte) []map[string]any {
	if len(body) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var items []map[string]any
	if decoder.Decode(&items) != nil {
		return nil
	}
	return items
}

func flattenStrings(input map[string]any) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string)
	var walk func(string, any)
	walk = func(prefix string, value any) {
		switch typed := value.(type) {
		case map[string]any:
			for key, nested := range typed {
				name := key
				if prefix != "" {
					name = prefix + "." + key
				}
				walk(name, nested)
			}
		case string:
			output[prefix] = typed
		case bool:
			output[prefix] = strconv.FormatBool(typed)
		case float64:
			output[prefix] = strconv.FormatFloat(typed, 'f', -1, 64)
		case json.Number:
			output[prefix] = typed.String()
		case nil:
		default:
			output[prefix] = fmt.Sprint(typed)
		}
	}
	for key, value := range input {
		walk(key, value)
	}
	return output
}

func parseInt(value any) int64 {
	switch typed := value.(type) {
	case string:
		if typed == "" || typed == "-" {
			return 0
		}
		parsed, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || typed > math.MaxInt64 || typed < math.MinInt64 {
			return 0
		}
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	default:
		return 0
	}
}

func parseFloat(value any) float64 {
	switch typed := value.(type) {
	case string:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return 0
		}
		return typed
	case json.Number:
		parsed, _ := typed.Float64()
		return parsed
	default:
		return 0
	}
}

func parseTime(value string) time.Time {
	value = strings.TrimSpace(value)
	formats := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05Z", "2006-01-02"}
	for _, format := range formats {
		parsed, err := time.Parse(format, value)
		if err == nil {
			return parsed.UTC()
		}
	}
	if millis, err := strconv.ParseInt(value, 10, 64); err == nil && millis > 0 {
		return time.UnixMilli(millis).UTC()
	}
	return time.Time{}
}

func mapValue(input map[string]any, path ...string) any {
	var current any = input
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[key]
	}
	return current
}

func mapObject(input map[string]any, path ...string) map[string]any {
	value, _ := mapValue(input, path...).(map[string]any)
	return value
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}
