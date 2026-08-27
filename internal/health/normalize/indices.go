package normalize

import (
	"strconv"
	"strings"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

func parseIndices(catBody, settingsBody []byte) []healthmodel.Index {
	settings := parseIndexSettings(settingsBody)
	items := decodeArray(catBody)
	indices := make([]healthmodel.Index, 0, len(items))
	for _, item := range items {
		name := stringValue(item["index"])
		if name == "" {
			continue
		}
		indexSettings := settings[name]
		index := healthmodel.Index{
			Name: name, UUID: stringValue(item["uuid"]), Health: stringValue(item["health"]), Status: stringValue(item["status"]),
			PrimaryShards: int(parseInt(item["pri"])), Replicas: int(parseInt(item["rep"])), Documents: parseInt(item["docs.count"]),
			DeletedDocuments: parseInt(item["docs.deleted"]), StoreBytes: parseInt(item["store.size"]), PrimaryStoreBytes: parseInt(item["pri.store.size"]),
			CreationTime: parseTime(stringValue(item["creation.date.string"])), Settings: indexSettings, System: strings.HasPrefix(name, "."),
		}
		if index.CreationTime.IsZero() {
			index.CreationTime = parseTime(indexSettings["index.creation_date"])
		}
		index.ILMPolicy = indexSettings["index.lifecycle.name"]
		if index.PrimaryShards == 0 {
			index.PrimaryShards = intString(indexSettings["index.number_of_shards"])
		}
		if _, present := item["rep"]; !present {
			index.Replicas = intString(indexSettings["index.number_of_replicas"])
		}
		indices = append(indices, index)
	}
	return indices
}

func parseIndexSettings(body []byte) map[string]map[string]string {
	root := decodeObject(body)
	result := make(map[string]map[string]string, len(root))
	for name, raw := range root {
		object, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		settings := flattenStrings(mapObject(object, "settings"))
		if len(settings) > 0 {
			result[name] = settings
		}
	}
	return result
}

func parseShards(body []byte) []healthmodel.Shard {
	items := decodeArray(body)
	shards := make([]healthmodel.Shard, 0, len(items))
	for _, item := range items {
		index := stringValue(item["index"])
		if index == "" {
			continue
		}
		shards = append(shards, healthmodel.Shard{
			Index: index, Number: int(parseInt(item["shard"])), Primary: strings.EqualFold(stringValue(item["prirep"]), "p"),
			State: strings.ToUpper(stringValue(item["state"])), Documents: parseInt(item["docs"]), StoreBytes: parseInt(item["store"]),
			IP: stringValue(item["ip"]), Node: stringValue(item["node"]), UnassignedReason: stringValue(item["unassigned.reason"]), UnassignedAt: stringValue(item["unassigned.at"]),
		})
	}
	return shards
}

func intString(value string) int {
	parsed, _ := strconv.Atoi(strings.TrimSpace(value))
	return parsed
}

func applyDataStreamMetadata(indices []healthmodel.Index, streams []healthmodel.DataStream) {
	byIndex := make(map[string]string)
	for _, stream := range streams {
		for _, index := range stream.BackingIndices {
			byIndex[index] = stream.Name
		}
	}
	for position := range indices {
		if stream := byIndex[indices[position].Name]; stream != "" {
			indices[position].DataStream = stream
		}
	}
}
