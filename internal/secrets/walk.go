package secrets

import (
	"strconv"
	"strings"
)

type walkLimits struct {
	maxDepth          int
	maxArrayItems     int
	maxObjectSize     int
	maxFieldBytes     int
	scanGenericFields bool
	entropyEnabled    bool
	broadCorrelation  bool
}

type walkStats struct {
	fields int
	bytes  int64
}

type walkResult struct {
	hits  []hit
	stats walkStats
}

func walkDocument(source any, limits walkLimits) []hit {
	result := walkDocumentStats(source, limits)
	return result.hits
}

func walkDocumentStats(source any, limits walkLimits) walkResult {
	result := &walkResult{}
	walkValue(source, "", 0, limits, result)
	return *result
}

func walkValue(value any, path string, depth int, limits walkLimits, result *walkResult) {
	if result == nil || depth > limits.maxDepth {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		walkObject(typed, path, depth, limits, result)
	case []any:
		walkArray(typed, path, depth, limits, result)
	case string:
		if typed == "" {
			return
		}
		result.stats.fields++
		result.stats.bytes += int64(len(typed))
		for _, item := range detectValue(typed, AnalyzeField(path), limits.maxFieldBytes) {
			if item.FieldPath == "" {
				item.FieldPath = path
			}
			result.hits = append(result.hits, item)
		}
		if strings.Contains(typed, "\n") {
			result.hits = append(result.hits, correlateTextBlock(typed, path, limits.broadCorrelation)...)
		}
	case []byte:
		walkValue(string(typed), path, depth, limits, result)
	}
}

func walkObject(object map[string]any, path string, depth int, limits walkLimits, result *walkResult) {
	if len(object) > limits.maxObjectSize {
		return
	}
	fields := make([]scopedField, 0, len(object))
	for key, child := range object {
		childPath := joinPath(path, key)
		if text, ok := child.(string); ok && text != "" {
			fields = append(fields, scopedField{
				Path:       childPath,
				Name:       key,
				ObjectPath: path,
				Value:      text,
			})
		}
		walkValue(child, childPath, depth+1, limits, result)
	}
	result.hits = append(result.hits, CorrelateScope(fields, path, limits.broadCorrelation)...)
}

func walkArray(items []any, path string, depth int, limits walkLimits, result *walkResult) {
	limit := limits.maxArrayItems
	if limit > len(items) {
		limit = len(items)
	}
	for index := 0; index < limit; index++ {
		childPath := path + "[" + strconv.Itoa(index) + "]"
		walkValue(items[index], childPath, depth+1, limits, result)
	}
}

func joinPath(parent, child string) string {
	child = strings.TrimSpace(child)
	if parent == "" {
		return child
	}
	if child == "" {
		return parent
	}
	return parent + "." + child
}

func mappingFields(mapping any, prefix string, depth int, limits walkLimits) []FieldSemantics {
	var fields []FieldSemantics
	object, ok := mapping.(map[string]any)
	if !ok || depth > limits.maxDepth {
		return fields
	}
	if properties, ok := object["properties"].(map[string]any); ok {
		return mappingFields(properties, prefix, depth, limits)
	}
	count := 0
	for name, raw := range object {
		if count >= limits.maxObjectSize {
			break
		}
		count++
		path := joinPath(prefix, name)
		child, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if nested, ok := child["properties"].(map[string]any); ok {
			fields = append(fields, mappingFields(nested, path, depth+1, limits)...)
			continue
		}
		semantics := AnalyzeField(path)
		if esType, ok := child["type"].(string); ok {
			semantics.ESType = esType
		}
		fields = append(fields, semantics)
		if fieldsMap, ok := child["fields"].(map[string]any); ok {
			fields = append(fields, mappingFields(fieldsMap, path, depth+1, limits)...)
		}
	}
	return fields
}

func sourceIncludes(fields []FieldSemantics, maxFields int, generic bool) []string {
	type ranked struct {
		path  string
		score int
	}
	var selected []ranked
	seen := make(map[string]struct{})
	for _, field := range fields {
		score := mappingPriority(field, generic)
		if score == 0 {
			continue
		}
		root := strings.Split(field.Path, ".")[0]
		root = strings.Split(root, "[")[0]
		if _, exists := seen[root]; exists {
			continue
		}
		seen[root] = struct{}{}
		selected = append(selected, ranked{path: root, score: score})
	}
	if len(selected) == 0 {
		return nil
	}
	for i := 0; i < len(selected); i++ {
		for j := i + 1; j < len(selected); j++ {
			if selected[j].score > selected[i].score {
				selected[i], selected[j] = selected[j], selected[i]
			}
		}
	}
	if maxFields > 0 && len(selected) > maxFields {
		selected = selected[:maxFields]
	}
	out := make([]string, 0, len(selected))
	for _, item := range selected {
		out = append(out, item.path)
	}
	return out
}
