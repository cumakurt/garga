package logging

import "log/slog"

// Bounded returns a string attribute whose value is taken from a closed set.
// Unknown values become "other" so user-controlled input cannot explode cardinality.
func Bounded(key, value string, allowed ...string) slog.Attr {
	for _, item := range allowed {
		if value == item {
			return slog.String(key, value)
		}
	}
	return slog.String(key, "other")
}
