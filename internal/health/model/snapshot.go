package model

import "time"

const SnapshotSchemaVersion = "1.0"

// ClusterSnapshot is the normalized, I/O-free input consumed by health checkers.
type ClusterSnapshot struct {
	SchemaVersion   string             `json:"schema_version"`
	Timestamp       time.Time          `json:"timestamp"`
	Target          string             `json:"target"`
	Cluster         ClusterInfo        `json:"cluster"`
	ClusterHealth   ClusterHealth      `json:"cluster_health"`
	ClusterSettings ClusterSettings    `json:"cluster_settings"`
	Nodes           []Node             `json:"nodes"`
	Indices         []Index            `json:"indices"`
	Shards          []Shard            `json:"shards"`
	PendingTasks    []PendingTask      `json:"pending_tasks,omitempty"`
	Tasks           []Task             `json:"tasks,omitempty"`
	ILM             ILMState           `json:"ilm,omitempty"`
	DataStreams     []DataStream       `json:"data_streams,omitempty"`
	Snapshots       SnapshotState      `json:"snapshots,omitempty"`
	Allocation      *AllocationExplain `json:"allocation_explain,omitempty"`
	Security        SecurityState      `json:"security"`
	Collection      CollectionState    `json:"collection"`
	Baseline        *Baseline          `json:"-"`
}

type ClusterInfo struct {
	Name             string  `json:"name,omitempty"`
	UUID             string  `json:"uuid,omitempty"`
	Version          Version `json:"version"`
	Nodes            int     `json:"nodes"`
	DataNodes        int     `json:"data_nodes"`
	Indices          int     `json:"indices"`
	Shards           int     `json:"shards"`
	Documents        int64   `json:"documents"`
	StoreBytes       int64   `json:"store_bytes"`
	Available        bool    `json:"available"`
	FingerprintValid bool    `json:"fingerprint_valid"`
}

type ClusterHealth struct {
	Status                      string  `json:"status,omitempty"`
	NumberOfNodes               int     `json:"number_of_nodes"`
	NumberOfDataNodes           int     `json:"number_of_data_nodes"`
	ActivePrimaryShards         int     `json:"active_primary_shards"`
	ActiveShards                int     `json:"active_shards"`
	RelocatingShards            int     `json:"relocating_shards"`
	InitializingShards          int     `json:"initializing_shards"`
	UnassignedShards            int     `json:"unassigned_shards"`
	DelayedUnassignedShards     int     `json:"delayed_unassigned_shards"`
	PendingTasks                int     `json:"number_of_pending_tasks"`
	InFlightFetch               int     `json:"number_of_in_flight_fetch"`
	MaxTaskWaitMillis           int64   `json:"task_max_waiting_in_queue_millis"`
	ActiveShardsPercentAsNumber float64 `json:"active_shards_percent_as_number"`
}

type ClusterSettings struct {
	Defaults   map[string]string `json:"defaults,omitempty"`
	Persistent map[string]string `json:"persistent,omitempty"`
	Transient  map[string]string `json:"transient,omitempty"`
}

// Effective returns the highest-precedence cluster setting.
func (settings ClusterSettings) Effective(key string) (string, bool) {
	if value, ok := settings.Transient[key]; ok && value != "" {
		return value, true
	}
	if value, ok := settings.Persistent[key]; ok && value != "" {
		return value, true
	}
	value, ok := settings.Defaults[key]
	return value, ok && value != ""
}

type Node struct {
	ID                  string                `json:"id"`
	Name                string                `json:"name"`
	IP                  string                `json:"ip,omitempty"`
	Roles               []string              `json:"roles,omitempty"`
	AvailableProcessors int                   `json:"available_processors"`
	JVM                 JVMStats              `json:"jvm"`
	CPU                 CPUStats              `json:"cpu"`
	Memory              MemoryStats           `json:"memory"`
	Filesystem          FilesystemStats       `json:"filesystem"`
	OpenFileDescriptors int64                 `json:"open_file_descriptors"`
	MaxFileDescriptors  int64                 `json:"max_file_descriptors"`
	ThreadPools         map[string]ThreadPool `json:"thread_pools,omitempty"`
	Breakers            map[string]Breaker    `json:"breakers,omitempty"`
	Indices             NodeIndexStats        `json:"indices"`
	IndexingPressure    IndexingPressure      `json:"indexing_pressure"`
	SecuritySettings    map[string]string     `json:"-"`
}

func (node Node) HasDataRole() bool {
	for _, role := range node.Roles {
		if role == "data" || len(role) > 5 && role[:5] == "data_" {
			return true
		}
	}
	return false
}

type JVMStats struct {
	Version            string `json:"version,omitempty"`
	HeapMaxBytes       int64  `json:"heap_max_bytes"`
	HeapCommittedBytes int64  `json:"heap_committed_bytes"`
	HeapUsedBytes      int64  `json:"heap_used_bytes"`
	HeapUsedPercent    int    `json:"heap_used_percent"`
	NonHeapUsedBytes   int64  `json:"non_heap_used_bytes"`
	YoungGCCount       int64  `json:"young_gc_count"`
	YoungGCTimeMillis  int64  `json:"young_gc_time_millis"`
	OldGCCount         int64  `json:"old_gc_count"`
	OldGCTimeMillis    int64  `json:"old_gc_time_millis"`
}

type CPUStats struct {
	ProcessPercent int        `json:"process_percent"`
	OSPercent      int        `json:"os_percent"`
	LoadAverage    [3]float64 `json:"load_average"`
}

type MemoryStats struct {
	TotalBytes int64 `json:"total_bytes"`
	FreeBytes  int64 `json:"free_bytes"`
	UsedBytes  int64 `json:"used_bytes"`
	SwapTotal  int64 `json:"swap_total_bytes"`
	SwapUsed   int64 `json:"swap_used_bytes"`
}

type FilesystemStats struct {
	TotalBytes     int64 `json:"total_bytes"`
	AvailableBytes int64 `json:"available_bytes"`
	DataPaths      int   `json:"data_paths"`
}

func (filesystem FilesystemStats) UsedBytes() int64 {
	used := filesystem.TotalBytes - filesystem.AvailableBytes
	if used < 0 {
		return 0
	}
	return used
}

func (filesystem FilesystemStats) UsedPercent() float64 {
	if filesystem.TotalBytes <= 0 {
		return 0
	}
	return float64(filesystem.UsedBytes()) / float64(filesystem.TotalBytes) * 100
}

type ThreadPool struct {
	Threads   int   `json:"threads"`
	Active    int   `json:"active"`
	Queue     int   `json:"queue"`
	Rejected  int64 `json:"rejected"`
	Completed int64 `json:"completed"`
}

type Breaker struct {
	EstimatedBytes int64   `json:"estimated_bytes"`
	LimitBytes     int64   `json:"limit_bytes"`
	Overhead       float64 `json:"overhead"`
	Tripped        int64   `json:"tripped"`
}

type NodeIndexStats struct {
	IndexTotal               int64 `json:"index_total"`
	IndexTimeMillis          int64 `json:"index_time_millis"`
	IndexCurrent             int64 `json:"index_current"`
	IndexFailed              int64 `json:"index_failed"`
	QueryTotal               int64 `json:"query_total"`
	QueryTimeMillis          int64 `json:"query_time_millis"`
	QueryCurrent             int64 `json:"query_current"`
	FetchTotal               int64 `json:"fetch_total"`
	FetchTimeMillis          int64 `json:"fetch_time_millis"`
	RefreshTotal             int64 `json:"refresh_total"`
	RefreshTimeMillis        int64 `json:"refresh_time_millis"`
	MergeCurrent             int64 `json:"merge_current"`
	MergeCurrentDocs         int64 `json:"merge_current_docs"`
	MergeCurrentBytes        int64 `json:"merge_current_bytes"`
	MergeTotal               int64 `json:"merge_total"`
	MergeThrottledTimeMillis int64 `json:"merge_throttled_time_millis"`
	SegmentCount             int64 `json:"segment_count"`
	SegmentMemoryBytes       int64 `json:"segment_memory_bytes"`
	FielddataMemoryBytes     int64 `json:"fielddata_memory_bytes"`
	FielddataEvictions       int64 `json:"fielddata_evictions"`
	QueryCacheMemoryBytes    int64 `json:"query_cache_memory_bytes"`
	QueryCacheHits           int64 `json:"query_cache_hits"`
	QueryCacheMisses         int64 `json:"query_cache_misses"`
	QueryCacheEvictions      int64 `json:"query_cache_evictions"`
	RequestCacheMemoryBytes  int64 `json:"request_cache_memory_bytes"`
	RequestCacheHits         int64 `json:"request_cache_hits"`
	RequestCacheMisses       int64 `json:"request_cache_misses"`
	RequestCacheEvictions    int64 `json:"request_cache_evictions"`
}

type IndexingPressure struct {
	CoordinatingBytes      int64 `json:"coordinating_bytes"`
	PrimaryBytes           int64 `json:"primary_bytes"`
	ReplicaBytes           int64 `json:"replica_bytes"`
	MemoryLimitBytes       int64 `json:"memory_limit_bytes"`
	CoordinatingRejections int64 `json:"coordinating_rejections"`
	PrimaryRejections      int64 `json:"primary_rejections"`
	ReplicaRejections      int64 `json:"replica_rejections"`
}

type Index struct {
	Name              string            `json:"name"`
	UUID              string            `json:"uuid,omitempty"`
	Health            string            `json:"health,omitempty"`
	Status            string            `json:"status,omitempty"`
	PrimaryShards     int               `json:"primary_shards"`
	Replicas          int               `json:"replicas"`
	Documents         int64             `json:"documents"`
	DeletedDocuments  int64             `json:"deleted_documents"`
	StoreBytes        int64             `json:"store_bytes"`
	PrimaryStoreBytes int64             `json:"primary_store_bytes"`
	CreationTime      time.Time         `json:"creation_time,omitempty"`
	Settings          map[string]string `json:"settings,omitempty"`
	System            bool              `json:"system"`
	DataStream        string            `json:"data_stream,omitempty"`
	ILMPolicy         string            `json:"ilm_policy,omitempty"`
}

func (index Index) DeletedRatio() float64 {
	total := index.Documents + index.DeletedDocuments
	if total <= 0 {
		return 0
	}
	return float64(index.DeletedDocuments) / float64(total)
}

type Shard struct {
	Index            string `json:"index"`
	Number           int    `json:"number"`
	Primary          bool   `json:"primary"`
	State            string `json:"state"`
	Documents        int64  `json:"documents"`
	StoreBytes       int64  `json:"store_bytes"`
	IP               string `json:"ip,omitempty"`
	Node             string `json:"node,omitempty"`
	UnassignedReason string `json:"unassigned_reason,omitempty"`
	UnassignedAt     string `json:"unassigned_at,omitempty"`
}

type PendingTask struct {
	InsertOrder int64  `json:"insert_order"`
	Priority    string `json:"priority"`
	Source      string `json:"source"`
	QueueMillis int64  `json:"queue_millis"`
	Executing   bool   `json:"executing"`
}

type Task struct {
	Node         string `json:"node"`
	ID           int64  `json:"id"`
	Type         string `json:"type,omitempty"`
	Action       string `json:"action,omitempty"`
	Description  string `json:"description,omitempty"`
	RunningNanos int64  `json:"running_nanos"`
}

type ILMState struct {
	Available bool       `json:"available"`
	Indices   []ILMIndex `json:"indices,omitempty"`
}

type ILMIndex struct {
	Index      string `json:"index"`
	Managed    bool   `json:"managed"`
	Policy     string `json:"policy,omitempty"`
	Phase      string `json:"phase,omitempty"`
	Action     string `json:"action,omitempty"`
	Step       string `json:"step,omitempty"`
	FailedStep string `json:"failed_step,omitempty"`
	StepInfo   string `json:"step_info,omitempty"`
}

type DataStream struct {
	Name             string   `json:"name"`
	Generation       int64    `json:"generation"`
	BackingIndices   []string `json:"backing_indices,omitempty"`
	ILMPolicy        string   `json:"ilm_policy,omitempty"`
	LifecycleEnabled bool     `json:"lifecycle_enabled"`
}

type SnapshotState struct {
	Available              bool       `json:"available"`
	Repositories           int        `json:"repositories"`
	RepositoriesChecked    int        `json:"repositories_checked"`
	RepositoryLimitReached bool       `json:"repository_limit_reached"`
	HistoryLimitReached    bool       `json:"history_limit_reached,omitempty"`
	Latest                 *Snapshot  `json:"latest,omitempty"`
	Failures               []Snapshot `json:"failures,omitempty"`
}

type Snapshot struct {
	Repository string    `json:"repository"`
	Name       string    `json:"name"`
	State      string    `json:"state"`
	StartTime  time.Time `json:"start_time,omitempty"`
	EndTime    time.Time `json:"end_time,omitempty"`
	Failures   int       `json:"failures"`
}

type AllocationExplain struct {
	Index                 string           `json:"index,omitempty"`
	Shard                 int              `json:"shard"`
	Primary               bool             `json:"primary"`
	Reason                string           `json:"reason,omitempty"`
	FailedAllocationCount int              `json:"failed_allocation_count"`
	LastAllocationStatus  string           `json:"last_allocation_status,omitempty"`
	CandidateNodes        []AllocationNode `json:"candidate_nodes,omitempty"`
}

type AllocationNode struct {
	Name     string `json:"name,omitempty"`
	Decision string `json:"decision,omitempty"`
	Deciders string `json:"deciders,omitempty"`
}

type SecurityState struct {
	HTTPSEnabled         bool         `json:"https_enabled"`
	Authenticated        bool         `json:"authenticated"`
	AnonymousAccess      bool         `json:"anonymous_access"`
	AuthenticationStatus int          `json:"authentication_status,omitempty"`
	HTTPSSLEnabled       *bool        `json:"http_tls_configured,omitempty"`
	TransportSSLEnabled  *bool        `json:"transport_tls_configured,omitempty"`
	AnonymousConfigured  *bool        `json:"anonymous_configured,omitempty"`
	Certificate          *Certificate `json:"certificate,omitempty"`
	CredentialsUsed      bool         `json:"-"`
	AllowPlaintextAuth   bool         `json:"allow_plaintext_auth,omitempty"`
}

type Certificate struct {
	Subject       string    `json:"subject,omitempty"`
	Issuer        string    `json:"issuer,omitempty"`
	ValidFrom     time.Time `json:"valid_from"`
	ValidUntil    time.Time `json:"valid_until"`
	RemainingDays int       `json:"remaining_days"`
	HostnameValid bool      `json:"hostname_valid"`
	SelfSigned    bool      `json:"self_signed"`
}

type CollectionState struct {
	Collectors []CollectorResult `json:"collectors"`
	Requests   int               `json:"requests"`
	Bytes      int64             `json:"bytes_downloaded"`
	Failed     int               `json:"failed_requests"`
	Retried    int               `json:"retried_requests"`
}

type CollectorResult struct {
	Name       string `json:"name"`
	Cost       string `json:"cost"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

const BaselineSchemaVersion = "1.0"

type Baseline struct {
	SchemaVersion     string                  `json:"schema_version"`
	Timestamp         time.Time               `json:"timestamp"`
	ClusterUUID       string                  `json:"cluster_uuid"`
	ClusterIndices    int                     `json:"cluster_indices"`
	ClusterShards     int                     `json:"cluster_shards"`
	ClusterDocuments  int64                   `json:"cluster_documents"`
	ClusterStoreBytes int64                   `json:"cluster_store_bytes"`
	Nodes             map[string]NodeCounters `json:"nodes"`
}

type NodeCounters struct {
	ThreadPoolRejected         map[string]int64 `json:"thread_pool_rejected,omitempty"`
	BreakerTrips               map[string]int64 `json:"breaker_trips,omitempty"`
	IndexingPressureRejections int64            `json:"indexing_pressure_rejections"`
	YoungGCCount               int64            `json:"young_gc_count"`
	YoungGCTimeMillis          int64            `json:"young_gc_time_millis"`
	OldGCCount                 int64            `json:"old_gc_count"`
	OldGCTimeMillis            int64            `json:"old_gc_time_millis"`
	QueryTotal                 int64            `json:"query_total"`
	QueryTimeMillis            int64            `json:"query_time_millis"`
	IndexTotal                 int64            `json:"index_total"`
	IndexTimeMillis            int64            `json:"index_time_millis"`
	IndexFailed                int64            `json:"index_failed"`
	FielddataEvictions         int64            `json:"fielddata_evictions"`
	QueryCacheEvictions        int64            `json:"query_cache_evictions"`
	RequestCacheEvictions      int64            `json:"request_cache_evictions"`
	RefreshTotal               int64            `json:"refresh_total"`
	RefreshTimeMillis          int64            `json:"refresh_time_millis"`
	MergeTotal                 int64            `json:"merge_total"`
	MergeThrottledTimeMillis   int64            `json:"merge_throttled_time_millis"`
	DiskTotalBytes             int64            `json:"disk_total_bytes"`
	DiskAvailableBytes         int64            `json:"disk_available_bytes"`
	HeapUsedBytes              int64            `json:"heap_used_bytes"`
	AssignedShards             int64            `json:"assigned_shards"`
}

// NewBaseline extracts only cumulative counters needed for delta analysis.
func NewBaseline(snapshot *ClusterSnapshot) Baseline {
	baseline := Baseline{
		SchemaVersion:     BaselineSchemaVersion,
		Timestamp:         snapshot.Timestamp,
		ClusterUUID:       snapshot.Cluster.UUID,
		ClusterIndices:    snapshot.Cluster.Indices,
		ClusterShards:     snapshot.Cluster.Shards,
		ClusterDocuments:  snapshot.Cluster.Documents,
		ClusterStoreBytes: snapshot.Cluster.StoreBytes,
		Nodes:             make(map[string]NodeCounters, len(snapshot.Nodes)),
	}
	shardsByNode := make(map[string]int64)
	for _, shard := range snapshot.Shards {
		if shard.Node != "" && shard.State != "UNASSIGNED" {
			shardsByNode[shard.Node]++
		}
	}
	for _, node := range snapshot.Nodes {
		rejected := make(map[string]int64, len(node.ThreadPools))
		for name, pool := range node.ThreadPools {
			rejected[name] = pool.Rejected
		}
		breakerTrips := make(map[string]int64, len(node.Breakers))
		for name, breaker := range node.Breakers {
			breakerTrips[name] = breaker.Tripped
		}
		baseline.Nodes[node.ID] = NodeCounters{
			ThreadPoolRejected:         rejected,
			BreakerTrips:               breakerTrips,
			IndexingPressureRejections: node.IndexingPressure.CoordinatingRejections + node.IndexingPressure.PrimaryRejections + node.IndexingPressure.ReplicaRejections,
			YoungGCCount:               node.JVM.YoungGCCount,
			YoungGCTimeMillis:          node.JVM.YoungGCTimeMillis,
			OldGCCount:                 node.JVM.OldGCCount,
			OldGCTimeMillis:            node.JVM.OldGCTimeMillis,
			QueryTotal:                 node.Indices.QueryTotal,
			QueryTimeMillis:            node.Indices.QueryTimeMillis,
			IndexTotal:                 node.Indices.IndexTotal,
			IndexTimeMillis:            node.Indices.IndexTimeMillis,
			IndexFailed:                node.Indices.IndexFailed,
			FielddataEvictions:         node.Indices.FielddataEvictions,
			QueryCacheEvictions:        node.Indices.QueryCacheEvictions,
			RequestCacheEvictions:      node.Indices.RequestCacheEvictions,
			RefreshTotal:               node.Indices.RefreshTotal,
			RefreshTimeMillis:          node.Indices.RefreshTimeMillis,
			MergeTotal:                 node.Indices.MergeTotal,
			MergeThrottledTimeMillis:   node.Indices.MergeThrottledTimeMillis,
			DiskTotalBytes:             node.Filesystem.TotalBytes,
			DiskAvailableBytes:         node.Filesystem.AvailableBytes,
			HeapUsedBytes:              node.JVM.HeapUsedBytes,
			AssignedShards:             shardsByNode[node.Name],
		}
	}
	return baseline
}
