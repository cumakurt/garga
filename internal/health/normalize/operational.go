package normalize

import (
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cumakurt/garga/internal/health/collector"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func parsePendingTasks(body []byte) []healthmodel.PendingTask {
	root := decodeObject(body)
	items, _ := root["tasks"].([]any)
	result := make([]healthmodel.PendingTask, 0, len(items))
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		result = append(result, healthmodel.PendingTask{
			InsertOrder: parseInt(item["insert_order"]), Priority: stringValue(item["priority"]), Source: boundedText(stringValue(item["source"]), 256),
			QueueMillis: parseInt(item["time_in_queue_millis"]), Executing: boolValue(item["executing"]),
		})
	}
	return result
}

func parseTasks(body []byte) []healthmodel.Task {
	root := decodeObject(body)
	var rawTasks []any
	switch tasks := root["tasks"].(type) {
	case []any:
		rawTasks = tasks
	case map[string]any:
		for _, raw := range tasks {
			rawTasks = append(rawTasks, raw)
		}
	}
	result := make([]healthmodel.Task, 0, len(rawTasks))
	for _, raw := range rawTasks {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		result = append(result, healthmodel.Task{
			Node: stringValue(item["node"]), ID: parseInt(item["id"]), Type: boundedText(stringValue(item["type"]), 128),
			Action: boundedText(stringValue(item["action"]), 256), Description: boundedText(stringValue(item["description"]), 512), RunningNanos: parseInt(item["running_time_in_nanos"]),
		})
	}
	return result
}

func parseILM(body []byte) healthmodel.ILMState {
	root := decodeObject(body)
	indices := mapObject(root, "indices")
	if len(indices) == 0 {
		return healthmodel.ILMState{}
	}
	state := healthmodel.ILMState{Available: true, Indices: make([]healthmodel.ILMIndex, 0, len(indices))}
	for name, raw := range indices {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		stepInfo := mapObject(item, "step_info")
		reason := stringValue(stepInfo["reason"])
		if reason == "" {
			reason = stringValue(stepInfo["type"])
		}
		state.Indices = append(state.Indices, healthmodel.ILMIndex{
			Index: name, Managed: boolValue(item["managed"]), Policy: stringValue(item["policy"]), Phase: stringValue(item["phase"]),
			Action: stringValue(item["action"]), Step: stringValue(item["step"]), FailedStep: stringValue(item["failed_step"]), StepInfo: boundedText(reason, 256),
		})
	}
	sort.Slice(state.Indices, func(left, right int) bool { return state.Indices[left].Index < state.Indices[right].Index })
	return state
}

func parseDataStreams(body []byte) []healthmodel.DataStream {
	root := decodeObject(body)
	items, _ := root["data_streams"].([]any)
	result := make([]healthmodel.DataStream, 0, len(items))
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		stream := healthmodel.DataStream{Name: stringValue(item["name"]), Generation: parseInt(item["generation"]), ILMPolicy: stringValue(item["ilm_policy"])}
		if lifecycle, ok := item["lifecycle"].(map[string]any); ok {
			if enabled, present := lifecycle["enabled"]; present {
				stream.LifecycleEnabled = boolValue(enabled)
			} else {
				stream.LifecycleEnabled = true
			}
		}
		if indices, ok := item["indices"].([]any); ok {
			for _, rawIndex := range indices {
				index, ok := rawIndex.(map[string]any)
				if ok && stringValue(index["index_name"]) != "" {
					stream.BackingIndices = append(stream.BackingIndices, stringValue(index["index_name"]))
				}
			}
		}
		if stream.Name != "" {
			result = append(result, stream)
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result
}

func parseSnapshots(responses collector.ResponseSet) healthmodel.SnapshotState {
	_, available := responses.Responses["snapshot_repositories"]
	state := healthmodel.SnapshotState{Available: available}
	if !available {
		return state
	}
	state.Repositories = len(decodeObject(responseBody(responses, "snapshot_repositories")))
	for _, result := range responses.Collectors {
		if result.Name == "snapshots_limit" && result.Reason == "repository_limit_reached" {
			state.RepositoryLimitReached = true
		}
	}
	var names []string
	for name := range responses.Responses {
		if strings.HasPrefix(name, "snapshots:") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		state.RepositoriesChecked++
		root := decodeObject(responseBody(responses, name))
		items, _ := root["snapshots"].([]any)
		snapshots := make([]healthmodel.Snapshot, 0, len(items))
		for _, raw := range items {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			snapshot := healthmodel.Snapshot{
				Repository: strings.TrimPrefix(name, "snapshots:"), Name: stringValue(item["snapshot"]), State: strings.ToUpper(stringValue(item["state"])),
				StartTime: parseTime(stringValue(item["start_time"])), EndTime: parseTime(stringValue(item["end_time"])),
			}
			if failures, ok := item["failures"].([]any); ok {
				snapshot.Failures = len(failures)
			}
			snapshots = append(snapshots, snapshot)
		}
		if len(snapshots) > maxSnapshotHistory {
			state.HistoryLimitReached = true
			sort.SliceStable(snapshots, func(left, right int) bool {
				return snapshotRecency(snapshots[left]).After(snapshotRecency(snapshots[right]))
			})
			snapshots = snapshots[:maxSnapshotHistory]
		}
		for _, snapshot := range snapshots {
			if snapshot.State == "SUCCESS" && (state.Latest == nil || snapshot.EndTime.After(state.Latest.EndTime)) {
				copy := snapshot
				state.Latest = &copy
			}
			if snapshot.State == "FAILED" || snapshot.State == "PARTIAL" || snapshot.Failures > 0 {
				state.Failures = append(state.Failures, snapshot)
			}
		}
	}
	return state
}

const maxSnapshotHistory = 20

func snapshotRecency(snapshot healthmodel.Snapshot) time.Time {
	if !snapshot.EndTime.IsZero() {
		return snapshot.EndTime
	}
	return snapshot.StartTime
}

func parseAllocation(body []byte) *healthmodel.AllocationExplain {
	root := decodeObject(body)
	if len(root) == 0 {
		return nil
	}
	allocation := &healthmodel.AllocationExplain{
		Index: stringValue(root["index"]), Shard: int(parseInt(root["shard"])), Primary: boolValue(root["primary"]),
	}
	if unassigned, ok := root["unassigned_info"].(map[string]any); ok {
		allocation.Reason = stringValue(unassigned["reason"])
		allocation.FailedAllocationCount = int(parseInt(unassigned["failed_allocation_attempts"]))
		allocation.LastAllocationStatus = stringValue(unassigned["last_allocation_status"])
	}
	if decisions, ok := root["node_allocation_decisions"].([]any); ok {
		for _, raw := range decisions {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			var deciders []string
			if list, ok := item["deciders"].([]any); ok {
				for _, rawDecider := range list {
					decider, ok := rawDecider.(map[string]any)
					if ok {
						deciders = append(deciders, stringValue(decider["decider"])+":"+stringValue(decider["decision"]))
					}
				}
			}
			allocation.CandidateNodes = append(allocation.CandidateNodes, healthmodel.AllocationNode{Name: stringValue(item["node_name"]), Decision: stringValue(item["node_decision"]), Deciders: strings.Join(deciders, ",")})
		}
	}
	return allocation
}

func boundedText(value string, maxBytes int) string {
	value = strings.ToValidUTF8(value, "")
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= maxBytes {
		return value
	}
	for maxBytes > 0 && !utf8.ValidString(value[:maxBytes]) {
		maxBytes--
	}
	return value[:maxBytes]
}
