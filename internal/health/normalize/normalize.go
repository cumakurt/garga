package normalize

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/health/collector"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
	basemodel "github.com/cumakurt/garga/internal/model"
)

// Build converts bounded Elasticsearch responses into one deterministic snapshot.
func Build(responses collector.ResponseSet, endpoint basemodel.Endpoint, usedCredential bool, timestamp time.Time) (*healthmodel.ClusterSnapshot, error) {
	root, ok := responses.Responses["root"]
	if !ok {
		return nil, fmt.Errorf("normalize health snapshot: root response is required")
	}
	target, err := endpoint.URL()
	if err != nil {
		return nil, fmt.Errorf("normalize health snapshot: target is invalid")
	}
	snapshot := &healthmodel.ClusterSnapshot{
		SchemaVersion: healthmodel.SnapshotSchemaVersion,
		Timestamp:     timestamp.UTC(),
		Target:        target,
		Collection: healthmodel.CollectionState{
			Collectors: append([]healthmodel.CollectorResult(nil), responses.Collectors...),
			Requests:   responses.Requests,
			Bytes:      responses.Bytes,
			Failed:     responses.Failed,
			Retried:    responses.Retried,
		},
		Security: healthmodel.SecurityState{HTTPSEnabled: endpoint.Scheme == basemodel.SchemeHTTPS},
	}
	if err := parseRoot(root.Body, &snapshot.Cluster); err != nil {
		return nil, err
	}
	snapshot.Cluster.FingerprintValid = true
	snapshot.Cluster.Available = true
	parseClusterHealth(responseBody(responses, "cluster_health"), &snapshot.ClusterHealth)
	parseClusterStats(responseBody(responses, "cluster_stats"), &snapshot.Cluster)
	parseClusterSettings(responseBody(responses, "cluster_settings"), &snapshot.ClusterSettings)
	snapshot.Nodes = parseNodes(responseBody(responses, "nodes_info"), responseBody(responses, "nodes_stats"))
	snapshot.Indices = parseIndices(responseBody(responses, "indices"), responseBody(responses, "index_settings"))
	snapshot.Shards = parseShards(responseBody(responses, "shards"))
	snapshot.PendingTasks = parsePendingTasks(responseBody(responses, "pending_tasks"))
	snapshot.Tasks = parseTasks(responseBody(responses, "tasks"))
	snapshot.ILM = parseILM(responseBody(responses, "ilm"))
	snapshot.DataStreams = parseDataStreams(responseBody(responses, "data_streams"))
	applyDataStreamMetadata(snapshot.Indices, snapshot.DataStreams)
	snapshot.Snapshots = parseSnapshots(responses)
	snapshot.Allocation = parseAllocation(responseBody(responses, "allocation_explain"))
	parseSecurity(responses, endpoint, usedCredential, snapshot)
	deriveCounts(snapshot)
	sortSnapshot(snapshot)
	return snapshot, nil
}

func responseBody(responses collector.ResponseSet, name string) []byte {
	response, ok := responses.Responses[name]
	if !ok {
		return nil
	}
	return response.Body
}

func parseRoot(body []byte, cluster *healthmodel.ClusterInfo) error {
	var root struct {
		ClusterName string `json:"cluster_name"`
		ClusterUUID string `json:"cluster_uuid"`
		Version     struct {
			Number                    string `json:"number"`
			BuildFlavor               string `json:"build_flavor"`
			BuildType                 string `json:"build_type"`
			BuildHash                 string `json:"build_hash"`
			LuceneVersion             string `json:"lucene_version"`
			MinimumWireCompatibility  string `json:"minimum_wire_compatibility_version"`
			MinimumIndexCompatibility string `json:"minimum_index_compatibility_version"`
			Distribution              string `json:"distribution"`
		} `json:"version"`
		Tagline string `json:"tagline"`
	}
	if err := json.Unmarshal(body, &root); err != nil {
		return fmt.Errorf("normalize health snapshot: root response is invalid: %w", err)
	}
	if root.Version.Number == "" || strings.EqualFold(root.Version.Distribution, "opensearch") || strings.Contains(strings.ToLower(root.Tagline), "opensearch") {
		return fmt.Errorf("normalize health snapshot: root response is not Elasticsearch")
	}
	cluster.Name = root.ClusterName
	cluster.UUID = root.ClusterUUID
	cluster.Version = healthmodel.Version{
		Number:                    root.Version.Number,
		BuildFlavor:               root.Version.BuildFlavor,
		BuildType:                 root.Version.BuildType,
		BuildHash:                 root.Version.BuildHash,
		LuceneVersion:             root.Version.LuceneVersion,
		MinimumWireCompatibility:  root.Version.MinimumWireCompatibility,
		MinimumIndexCompatibility: root.Version.MinimumIndexCompatibility,
	}
	return nil
}

func parseClusterHealth(body []byte, destination *healthmodel.ClusterHealth) {
	if len(body) == 0 {
		return
	}
	_ = json.Unmarshal(body, destination)
}

func parseClusterStats(body []byte, cluster *healthmodel.ClusterInfo) {
	if len(body) == 0 {
		return
	}
	var stats struct {
		ClusterName string `json:"cluster_name"`
		ClusterUUID string `json:"cluster_uuid"`
		Indices     struct {
			Count  int `json:"count"`
			Shards struct {
				Total int `json:"total"`
			} `json:"shards"`
			Docs struct {
				Count int64 `json:"count"`
			} `json:"docs"`
			Store struct {
				Size int64 `json:"size_in_bytes"`
			} `json:"store"`
		} `json:"indices"`
		Nodes struct {
			Count map[string]int `json:"count"`
		} `json:"nodes"`
	}
	if json.Unmarshal(body, &stats) != nil {
		return
	}
	if cluster.Name == "" {
		cluster.Name = stats.ClusterName
	}
	if cluster.UUID == "" {
		cluster.UUID = stats.ClusterUUID
	}
	cluster.Indices = stats.Indices.Count
	cluster.Shards = stats.Indices.Shards.Total
	cluster.Documents = stats.Indices.Docs.Count
	cluster.StoreBytes = stats.Indices.Store.Size
	cluster.Nodes = stats.Nodes.Count["total"]
	cluster.DataNodes = dataNodeCount(stats.Nodes.Count)
}

func dataNodeCount(counts map[string]int) int {
	if value := counts["data"]; value > 0 {
		return value
	}
	total := 0
	for role, count := range counts {
		if strings.HasPrefix(role, "data_") {
			total += count
		}
	}
	return total
}

func parseClusterSettings(body []byte, destination *healthmodel.ClusterSettings) {
	if len(body) == 0 {
		return
	}
	var response struct {
		Defaults   map[string]any `json:"defaults"`
		Persistent map[string]any `json:"persistent"`
		Transient  map[string]any `json:"transient"`
	}
	if json.Unmarshal(body, &response) != nil {
		return
	}
	destination.Defaults = flattenStrings(response.Defaults)
	destination.Persistent = flattenStrings(response.Persistent)
	destination.Transient = flattenStrings(response.Transient)
}

func deriveCounts(snapshot *healthmodel.ClusterSnapshot) {
	if snapshot.Cluster.Nodes == 0 {
		snapshot.Cluster.Nodes = len(snapshot.Nodes)
	}
	if snapshot.Cluster.DataNodes == 0 {
		for _, node := range snapshot.Nodes {
			if node.HasDataRole() {
				snapshot.Cluster.DataNodes++
			}
		}
	}
	if snapshot.Cluster.Indices == 0 {
		snapshot.Cluster.Indices = len(snapshot.Indices)
	}
	if snapshot.Cluster.Shards == 0 {
		snapshot.Cluster.Shards = len(snapshot.Shards)
	}
	if snapshot.Cluster.Documents == 0 || snapshot.Cluster.StoreBytes == 0 {
		var documents, storeBytes int64
		for _, index := range snapshot.Indices {
			documents += index.Documents
			storeBytes += index.StoreBytes
		}
		if snapshot.Cluster.Documents == 0 {
			snapshot.Cluster.Documents = documents
		}
		if snapshot.Cluster.StoreBytes == 0 {
			snapshot.Cluster.StoreBytes = storeBytes
		}
	}
	if snapshot.ClusterHealth.NumberOfNodes == 0 {
		snapshot.ClusterHealth.NumberOfNodes = snapshot.Cluster.Nodes
	}
	if snapshot.ClusterHealth.NumberOfDataNodes == 0 {
		snapshot.ClusterHealth.NumberOfDataNodes = snapshot.Cluster.DataNodes
	}
}

func sortSnapshot(snapshot *healthmodel.ClusterSnapshot) {
	sort.Slice(snapshot.Nodes, func(left, right int) bool {
		if snapshot.Nodes[left].Name != snapshot.Nodes[right].Name {
			return snapshot.Nodes[left].Name < snapshot.Nodes[right].Name
		}
		return snapshot.Nodes[left].ID < snapshot.Nodes[right].ID
	})
	sort.Slice(snapshot.Indices, func(left, right int) bool { return snapshot.Indices[left].Name < snapshot.Indices[right].Name })
	sort.Slice(snapshot.Shards, func(left, right int) bool {
		if snapshot.Shards[left].Index != snapshot.Shards[right].Index {
			return snapshot.Shards[left].Index < snapshot.Shards[right].Index
		}
		if snapshot.Shards[left].Number != snapshot.Shards[right].Number {
			return snapshot.Shards[left].Number < snapshot.Shards[right].Number
		}
		return snapshot.Shards[left].Primary && !snapshot.Shards[right].Primary
	})
}
