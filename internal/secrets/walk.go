package secrets

import (
	"context"
	"sort"
	"strconv"
	"strings"
)

type walkLimits struct {
	ctx               context.Context
	maxDepth          int
	maxArrayItems     int
	maxObjectSize     int
	maxFieldBytes     int
	scanGenericFields bool
	entropyEnabled    bool
	broadCorrelation  bool
	maxHits           int
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

func walkCancelled(limits walkLimits) bool {
	return limits.ctx != nil && limits.ctx.Err() != nil
}

func walkValue(value any, path string, depth int, limits walkLimits, result *walkResult) {
	if result == nil || depth > limits.maxDepth || hitLimitReached(result, limits) || walkCancelled(limits) {
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
		detected := detectValue(typed, AnalyzeField(path), limits.maxFieldBytes)
		if !limits.entropyEnabled {
			detected = withoutEntropyHits(detected)
		}
		for index := range detected {
			if detected[index].FieldPath == "" {
				detected[index].FieldPath = path
			}
		}
		appendWalkHits(result, limits, detected)
		if strings.Contains(typed, "\n") {
			appendWalkHits(result, limits, correlateTextBlock(typed, path, limits.broadCorrelation))
		}
	case []byte:
		walkValue(string(typed), path, depth, limits, result)
	}
}

func walkObject(object map[string]any, path string, depth int, limits walkLimits, result *walkResult) {
	keys := selectWalkKeys(object, limits.maxObjectSize)
	fields := make([]scopedField, 0, len(keys))
	for _, key := range keys {
		if hitLimitReached(result, limits) || walkCancelled(limits) {
			break
		}
		child := object[key]
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
	appendWalkHits(result, limits, CorrelateScope(fields, path, limits.broadCorrelation))
}

func selectWalkKeys(object map[string]any, limit int) []string {
	keys := sortedMapKeys(object)
	if limit <= 0 || len(keys) <= limit {
		return keys
	}
	sensitive := make([]string, 0, limit)
	rest := make([]string, 0, len(keys))
	for _, key := range keys {
		if AnalyzeField(key).Sensitive {
			sensitive = append(sensitive, key)
			continue
		}
		rest = append(rest, key)
	}
	selected := make([]string, 0, limit)
	selected = append(selected, sensitive...)
	if len(selected) > limit {
		return selected[:limit]
	}
	selected = append(selected, rest[:limit-len(selected)]...)
	sort.Strings(selected)
	return selected
}

func withoutEntropyHits(hits []hit) []hit {
	if len(hits) == 0 {
		return hits
	}
	out := make([]hit, 0, len(hits))
	for _, item := range hits {
		if item.Detector == "entropy" {
			continue
		}
		out = append(out, item)
	}
	return out
}

func walkArray(items []any, path string, depth int, limits walkLimits, result *walkResult) {
	limit := limits.maxArrayItems
	if limit > len(items) {
		limit = len(items)
	}
	for index := 0; index < limit; index++ {
		if hitLimitReached(result, limits) {
			break
		}
		childPath := path + "[" + strconv.Itoa(index) + "]"
		walkValue(items[index], childPath, depth+1, limits, result)
	}
}

func appendWalkHits(result *walkResult, limits walkLimits, hits []hit) {
	if result == nil || len(hits) == 0 {
		return
	}
	if limits.maxHits > 0 {
		remaining := limits.maxHits - len(result.hits)
		if remaining <= 0 {
			return
		}
		if len(hits) > remaining {
			hits = hits[:remaining]
		}
	}
	result.hits = append(result.hits, hits...)
}

func hitLimitReached(result *walkResult, limits walkLimits) bool {
	return limits.maxHits > 0 && len(result.hits) >= limits.maxHits
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
	if !ok || depth > limits.maxDepth || walkCancelled(limits) {
		return fields
	}
	if properties, ok := object["properties"].(map[string]any); ok {
		return mappingFields(properties, prefix, depth+1, limits)
	}
	count := 0
	for _, name := range sortedMapKeys(object) {
		if walkCancelled(limits) {
			break
		}
		if count >= limits.maxObjectSize {
			break
		}
		count++
		raw := object[name]
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
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].score != selected[j].score {
			return selected[i].score > selected[j].score
		}
		return selected[i].path < selected[j].path
	})
	if maxFields > 0 && len(selected) > maxFields {
		selected = selected[:maxFields]
	}
	out := make([]string, 0, len(selected))
	for _, item := range selected {
		out = append(out, item.path)
	}
	return out
}

func sortedMapKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
