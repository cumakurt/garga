package normalize

import (
	"sort"
	"strings"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func parseNodes(infoBody, statsBody []byte) []healthmodel.Node {
	nodes := make(map[string]*healthmodel.Node)
	infoRoot := decodeObject(infoBody)
	for id, raw := range mapObject(infoRoot, "nodes") {
		object, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		node := &healthmodel.Node{
			ID: id, Name: stringValue(object["name"]), Version: stringValue(object["version"]), IP: stringValue(object["ip"]), Roles: stringSlice(object["roles"]),
			ThreadPools: make(map[string]healthmodel.ThreadPool), Breakers: make(map[string]healthmodel.Breaker),
		}
		jvm := mapObject(object, "jvm")
		node.JVM.Version = stringValue(jvm["version"])
		node.JVM.Vendor = stringValue(jvm["vm_vendor"])
		node.JVM.HeapMaxBytes = parseInt(mapValue(jvm, "mem", "heap_max_in_bytes"))
		node.Components = parseNodeComponents(object)
		os := mapObject(object, "os")
		node.AvailableProcessors = int(parseInt(os["available_processors"]))
		process := mapObject(object, "process")
		node.MaxFileDescriptors = parseInt(process["max_file_descriptors"])
		node.SecuritySettings = securitySettings(mapObject(object, "settings"))
		nodes[id] = node
	}

	statsRoot := decodeObject(statsBody)
	for id, raw := range mapObject(statsRoot, "nodes") {
		object, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		node := nodes[id]
		if node == nil {
			node = &healthmodel.Node{ID: id, ThreadPools: make(map[string]healthmodel.ThreadPool), Breakers: make(map[string]healthmodel.Breaker)}
			nodes[id] = node
		}
		if node.Name == "" {
			node.Name = stringValue(object["name"])
		}
		if len(node.Roles) == 0 {
			node.Roles = stringSlice(object["roles"])
		}
		parseNodeJVM(object, node)
		parseNodeOS(object, node)
		parseNodeProcess(object, node)
		parseNodeFilesystem(object, node)
		parseThreadPools(object, node)
		parseBreakers(object, node)
		parseNodeIndices(object, node)
		parseIndexingPressure(object, node)
	}

	result := make([]healthmodel.Node, 0, len(nodes))
	for _, node := range nodes {
		if node.Name == "" {
			node.Name = node.ID
		}
		if len(node.ThreadPools) == 0 {
			node.ThreadPools = nil
		}
		if len(node.Breakers) == 0 {
			node.Breakers = nil
		}
		sort.Strings(node.Roles)
		sort.Slice(node.Components, func(left, right int) bool {
			if node.Components[left].Name != node.Components[right].Name {
				return node.Components[left].Name < node.Components[right].Name
			}
			return node.Components[left].Type < node.Components[right].Type
		})
		result = append(result, *node)
	}
	return result
}

func parseNodeComponents(object map[string]any) []healthmodel.NodeComponent {
	var result []healthmodel.NodeComponent
	seen := make(map[string]struct{})
	for _, field := range []struct {
		name, kind string
	}{{"modules", "module"}, {"plugins", "plugin"}} {
		items, _ := object[field.name].([]any)
		for _, raw := range items {
			component, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(stringValue(component["name"])))
			if name == "" || len(name) > 128 {
				continue
			}
			key := field.kind + "\x00" + name
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, healthmodel.NodeComponent{Name: name, Version: strings.TrimSpace(stringValue(component["version"])), Type: field.kind})
		}
	}
	return result
}

func parseNodeJVM(object map[string]any, node *healthmodel.Node) {
	jvm := mapObject(object, "jvm")
	mem := mapObject(jvm, "mem")
	node.JVM.HeapCommittedBytes = parseInt(mem["heap_committed_in_bytes"])
	node.JVM.HeapUsedBytes = parseInt(mem["heap_used_in_bytes"])
	node.JVM.HeapUsedPercent = int(parseInt(mem["heap_used_percent"]))
	node.JVM.NonHeapUsedBytes = parseInt(mem["non_heap_used_in_bytes"])
	if node.JVM.HeapMaxBytes == 0 {
		node.JVM.HeapMaxBytes = parseInt(mem["heap_max_in_bytes"])
	}
	for name, raw := range mapObject(jvm, "gc", "collectors") {
		collector, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		count := parseInt(collector["collection_count"])
		timeMillis := parseInt(collector["collection_time_in_millis"])
		switch strings.ToLower(name) {
		case "young":
			node.JVM.YoungGCCount += count
			node.JVM.YoungGCTimeMillis += timeMillis
		case "old":
			node.JVM.OldGCCount += count
			node.JVM.OldGCTimeMillis += timeMillis
		}
	}
}

func parseNodeOS(object map[string]any, node *healthmodel.Node) {
	os := mapObject(object, "os")
	if node.AvailableProcessors == 0 {
		node.AvailableProcessors = int(parseInt(os["available_processors"]))
	}
	node.CPU.OSPercent = int(parseInt(mapValue(os, "cpu", "percent")))
	load := mapObject(os, "cpu", "load_average")
	node.CPU.LoadAverage = [3]float64{parseFloat(load["1m"]), parseFloat(load["5m"]), parseFloat(load["15m"])}
	mem := mapObject(os, "mem")
	node.Memory.TotalBytes = parseInt(mem["total_in_bytes"])
	node.Memory.FreeBytes = parseInt(mem["free_in_bytes"])
	node.Memory.UsedBytes = parseInt(mem["used_in_bytes"])
	swap := mapObject(os, "swap")
	node.Memory.SwapTotal = parseInt(swap["total_in_bytes"])
	node.Memory.SwapUsed = parseInt(swap["used_in_bytes"])
}

func parseNodeProcess(object map[string]any, node *healthmodel.Node) {
	process := mapObject(object, "process")
	node.CPU.ProcessPercent = int(parseInt(mapValue(process, "cpu", "percent")))
	node.OpenFileDescriptors = parseInt(process["open_file_descriptors"])
	if node.MaxFileDescriptors == 0 {
		node.MaxFileDescriptors = parseInt(process["max_file_descriptors"])
	}
}

func parseNodeFilesystem(object map[string]any, node *healthmodel.Node) {
	filesystem := mapObject(object, "fs")
	total := mapObject(filesystem, "total")
	node.Filesystem.TotalBytes = parseInt(total["total_in_bytes"])
	node.Filesystem.AvailableBytes = parseInt(total["available_in_bytes"])
	if paths, ok := filesystem["data"].([]any); ok {
		node.Filesystem.DataPaths = len(paths)
	}
}

func parseThreadPools(object map[string]any, node *healthmodel.Node) {
	for name, raw := range mapObject(object, "thread_pool") {
		pool, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		node.ThreadPools[name] = healthmodel.ThreadPool{
			Threads: int(parseInt(pool["threads"])), Active: int(parseInt(pool["active"])), Queue: int(parseInt(pool["queue"])),
			Rejected: parseInt(pool["rejected"]), Completed: parseInt(pool["completed"]),
		}
	}
}

func parseBreakers(object map[string]any, node *healthmodel.Node) {
	for name, raw := range mapObject(object, "breakers") {
		breaker, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		node.Breakers[name] = healthmodel.Breaker{
			EstimatedBytes: parseInt(breaker["estimated_size_in_bytes"]), LimitBytes: parseInt(breaker["limit_size_in_bytes"]),
			Overhead: parseFloat(breaker["overhead"]), Tripped: parseInt(breaker["tripped"]),
		}
	}
}

func parseNodeIndices(object map[string]any, node *healthmodel.Node) {
	indices := mapObject(object, "indices")
	indexing := mapObject(indices, "indexing")
	search := mapObject(indices, "search")
	refresh := mapObject(indices, "refresh")
	merges := mapObject(indices, "merges")
	segments := mapObject(indices, "segments")
	fielddata := mapObject(indices, "fielddata")
	queryCache := mapObject(indices, "query_cache")
	requestCache := mapObject(indices, "request_cache")
	node.Indices = healthmodel.NodeIndexStats{
		IndexTotal: parseInt(indexing["index_total"]), IndexTimeMillis: parseInt(indexing["index_time_in_millis"]), IndexCurrent: parseInt(indexing["index_current"]), IndexFailed: parseInt(indexing["index_failed"]),
		QueryTotal: parseInt(search["query_total"]), QueryTimeMillis: parseInt(search["query_time_in_millis"]), QueryCurrent: parseInt(search["query_current"]), FetchTotal: parseInt(search["fetch_total"]), FetchTimeMillis: parseInt(search["fetch_time_in_millis"]),
		RefreshTotal: parseInt(refresh["total"]), RefreshTimeMillis: parseInt(refresh["total_time_in_millis"]),
		MergeCurrent: parseInt(merges["current"]), MergeCurrentDocs: parseInt(merges["current_docs"]), MergeCurrentBytes: parseInt(merges["current_size_in_bytes"]), MergeTotal: parseInt(merges["total"]), MergeThrottledTimeMillis: parseInt(merges["total_throttled_time_in_millis"]),
		SegmentCount: parseInt(segments["count"]), SegmentMemoryBytes: segmentMemory(segments),
		FielddataMemoryBytes: parseInt(fielddata["memory_size_in_bytes"]), FielddataEvictions: parseInt(fielddata["evictions"]),
		QueryCacheMemoryBytes: parseInt(queryCache["memory_size_in_bytes"]), QueryCacheHits: parseInt(queryCache["hit_count"]), QueryCacheMisses: parseInt(queryCache["miss_count"]), QueryCacheEvictions: parseInt(queryCache["evictions"]),
		RequestCacheMemoryBytes: parseInt(requestCache["memory_size_in_bytes"]), RequestCacheHits: parseInt(requestCache["hit_count"]), RequestCacheMisses: parseInt(requestCache["miss_count"]), RequestCacheEvictions: parseInt(requestCache["evictions"]),
	}
}

func segmentMemory(segments map[string]any) int64 {
	if total := parseInt(segments["memory_in_bytes"]); total > 0 {
		return total
	}
	keys := []string{"terms_memory_in_bytes", "stored_fields_memory_in_bytes", "term_vectors_memory_in_bytes", "norms_memory_in_bytes", "points_memory_in_bytes", "doc_values_memory_in_bytes", "index_writer_memory_in_bytes", "version_map_memory_in_bytes", "fixed_bit_set_memory_in_bytes"}
	var total int64
	for _, key := range keys {
		total += parseInt(segments[key])
	}
	return total
}

func parseIndexingPressure(object map[string]any, node *healthmodel.Node) {
	memory := mapObject(object, "indexing_pressure", "memory")
	current := mapObject(memory, "current")
	total := mapObject(memory, "total")
	node.IndexingPressure = healthmodel.IndexingPressure{
		CoordinatingBytes: parseInt(current["coordinating_in_bytes"]), PrimaryBytes: parseInt(current["primary_in_bytes"]), ReplicaBytes: parseInt(current["replica_in_bytes"]), MemoryLimitBytes: parseInt(memory["limit_in_bytes"]),
		CoordinatingRejections: parseInt(total["coordinating_rejections"]), PrimaryRejections: parseInt(total["primary_rejections"]), ReplicaRejections: parseInt(total["replica_rejections"]),
	}
}

func stringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok && text != "" {
			result = append(result, text)
		}
	}
	return result
}

func securitySettings(settings map[string]any) map[string]string {
	flattened := flattenStrings(settings)
	result := make(map[string]string)
	for key, value := range flattened {
		if strings.HasPrefix(key, "xpack.security.") && !sensitiveSetting(key) {
			result[key] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func sensitiveSetting(key string) bool {
	lower := strings.ToLower(key)
	for _, fragment := range []string{"password", "passwd", "authorization", "api_key", "token", "secret", "credential", "cookie", "secure_"} {
		if strings.Contains(lower, fragment) {
			return true
		}
	}
	return false
}
