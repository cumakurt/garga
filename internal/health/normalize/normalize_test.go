package normalize

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cumakurt/garga/internal/health/collector"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
	basemodel "github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/transport"
)

func TestBuildNormalizesElasticsearchVersions(t *testing.T) {
	t.Parallel()
	tests := []struct{ directory, version string }{{"es7", "7.17.23"}, {"es8", "8.19.19"}, {"es9", "9.4.4"}}
	for _, test := range tests {
		t.Run(test.directory, func(t *testing.T) {
			t.Parallel()
			root, err := os.ReadFile(filepath.Join("..", "testdata", test.directory, "root.json"))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			responses := fixtureResponses(root)
			snapshot, err := Build(responses, basemodel.Endpoint{Scheme: basemodel.SchemeHTTPS, Host: "es.example", Port: 9200}, true, time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if snapshot.Cluster.Version.Number != test.version || snapshot.Cluster.Nodes != 1 || snapshot.Cluster.Indices != 1 || snapshot.Cluster.Shards != 1 {
				t.Fatalf("snapshot identity/counts = %#v", snapshot.Cluster)
			}
			if len(snapshot.Nodes) != 1 || snapshot.Nodes[0].JVM.HeapUsedPercent != 88 || snapshot.Nodes[0].Filesystem.UsedPercent() != 90 {
				t.Fatalf("normalized node = %#v", snapshot.Nodes)
			}
			if len(snapshot.Indices) != 1 || snapshot.Indices[0].Replicas != 0 || len(snapshot.Shards) != 1 || snapshot.Shards[0].State != "STARTED" {
				t.Fatalf("normalized indices/shards = %#v / %#v", snapshot.Indices, snapshot.Shards)
			}
			if snapshot.Security.Certificate != nil || !snapshot.Security.HTTPSEnabled || !snapshot.Security.CredentialsUsed {
				t.Fatalf("security state = %#v", snapshot.Security)
			}
		})
	}
}

func TestBuildAnonymousAccessRequiresAuthenticateEvidence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	endpoint := basemodel.Endpoint{Scheme: basemodel.SchemeHTTP, Host: "es.example", Port: 9200}
	tests := []struct {
		name           string
		status         int
		body           string
		usedCredential bool
		wantAnonymous  bool
	}{
		{name: "required auth", status: 401, body: `{}`, wantAnonymous: false},
		{name: "anonymous identity", status: 200, body: `{"username":"_anonymous","authentication_type":"anonymous"}`, wantAnonymous: true},
		{name: "unauthenticated success", status: 200, body: `{"username":"elastic","authentication_type":"realm"}`, wantAnonymous: true},
		{name: "authenticated success", status: 200, body: `{"username":"elastic","authentication_type":"realm"}`, usedCredential: true, wantAnonymous: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			responses := fixtureResponses([]byte(`{"cluster_name":"fixture","cluster_uuid":"uuid","version":{"number":"8.19.19"}}`))
			responses.Responses["authenticate"] = transport.Response{StatusCode: test.status, Body: []byte(test.body)}
			snapshot, err := Build(responses, endpoint, test.usedCredential, now)
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if snapshot.Security.AnonymousAccess != test.wantAnonymous {
				t.Fatalf("AnonymousAccess = %t, want %t", snapshot.Security.AnonymousAccess, test.wantAnonymous)
			}
		})
	}
}

func TestBuildNormalizesNodeRuntimeInventory(t *testing.T) {
	t.Parallel()

	responses := fixtureResponses([]byte(`{"cluster_name":"fixture","cluster_uuid":"uuid","version":{"number":"8.19.19"}}`))
	responses.Responses["nodes_info"] = transport.Response{StatusCode: 200, Body: []byte(`{"nodes":{"node-1":{"name":"data-1","version":"8.19.19","roles":["data_hot"],"jvm":{"version":"21.0.4","vm_vendor":"Eclipse Adoptium"},"modules":[{"name":"ingest-attachment","version":"8.19.19"}],"plugins":[{"name":"repository-s3","version":"8.19.19"}]}}}`)}
	snapshot, err := Build(responses, basemodel.Endpoint{Scheme: basemodel.SchemeHTTPS, Host: "es.example", Port: 9200}, true, time.Now())
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	node := snapshot.Nodes[0]
	if node.Version != "8.19.19" || node.JVM.Vendor != "Eclipse Adoptium" || len(node.Components) != 2 {
		t.Fatalf("runtime inventory = %#v", node)
	}
	if node.Components[0].Name != "ingest-attachment" || node.Components[0].Type != "module" {
		t.Fatalf("components = %#v", node.Components)
	}
}

func TestBuildCapsSnapshotHistoryPerRepository(t *testing.T) {
	t.Parallel()
	responses := fixtureResponses([]byte(`{"cluster_name":"fixture","cluster_uuid":"uuid","version":{"number":"8.19.19"}}`))
	responses.Responses["snapshot_repositories"] = transport.Response{StatusCode: 200, Body: []byte(`{"fs-repo":{"type":"fs"}}`)}
	var snapshots []map[string]any
	for index := 0; index < 25; index++ {
		snapshots = append(snapshots, map[string]any{
			"snapshot":   fmt.Sprintf("snap-%02d", index),
			"state":      "SUCCESS",
			"start_time": fmt.Sprintf("2026-08-%02dT00:00:00Z", index+1),
			"end_time":   fmt.Sprintf("2026-08-%02dT01:00:00Z", index+1),
		})
	}
	payload, err := json.Marshal(map[string]any{"snapshots": snapshots})
	if err != nil {
		t.Fatal(err)
	}
	responses.Responses["snapshots:fs-repo"] = transport.Response{StatusCode: 200, Body: payload}
	snapshot, err := Build(responses, basemodel.Endpoint{Scheme: basemodel.SchemeHTTPS, Host: "es.example", Port: 9200}, true, time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !snapshot.Snapshots.HistoryLimitReached || snapshot.Snapshots.Latest == nil || snapshot.Snapshots.Latest.Name != "snap-24" {
		t.Fatalf("snapshot state = %#v", snapshot.Snapshots)
	}
}

func TestBuildRejectsMalformedRoot(t *testing.T) {
	t.Parallel()
	responses := fixtureResponses([]byte(`{"version":{"number":false}}`))
	if _, err := Build(responses, basemodel.Endpoint{Scheme: basemodel.SchemeHTTP, Host: "localhost", Port: 9200}, false, time.Now()); err == nil {
		t.Fatal("Build() accepted malformed root response")
	}
}

func FuzzBuildRoot(f *testing.F) {
	f.Add([]byte(`{"cluster_name":"fixture","cluster_uuid":"uuid","version":{"number":"8.19.19"}}`))
	f.Fuzz(func(t *testing.T, root []byte) {
		responses := fixtureResponses(root)
		_, _ = Build(responses, basemodel.Endpoint{Scheme: basemodel.SchemeHTTP, Host: "localhost", Port: 9200}, false, time.Now())
	})
}

func BenchmarkBuild(b *testing.B) {
	root, err := os.ReadFile(filepath.Join("..", "testdata", "es8", "root.json"))
	if err != nil {
		b.Fatal(err)
	}
	responses := fixtureResponses(root)
	endpoint := basemodel.Endpoint{Scheme: basemodel.SchemeHTTPS, Host: "es.example", Port: 9200}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Build(responses, endpoint, true, now); err != nil {
			b.Fatal(err)
		}
	}
}

func fixtureResponses(root []byte) collector.ResponseSet {
	responses := map[string]transport.Response{
		"root":             {StatusCode: 200, Body: root},
		"cluster_health":   {StatusCode: 200, Body: []byte(`{"status":"green","number_of_nodes":1,"number_of_data_nodes":1,"active_primary_shards":1,"active_shards":1,"active_shards_percent_as_number":100}`)},
		"cluster_stats":    {StatusCode: 200, Body: []byte(`{"indices":{"count":1,"shards":{"total":1},"docs":{"count":100},"store":{"size_in_bytes":1000}},"nodes":{"count":{"total":1,"data":1}}}`)},
		"cluster_settings": {StatusCode: 200, Body: []byte(`{"defaults":{"cluster.routing.allocation.disk.watermark.low":"85%"},"persistent":{},"transient":{}}`)},
		"nodes_info":       {StatusCode: 200, Body: []byte(`{"nodes":{"node-1":{"name":"data-1","ip":"127.0.0.1","roles":["data_hot"],"jvm":{"version":"21","mem":{"heap_max_in_bytes":1000}},"os":{"available_processors":4},"process":{"max_file_descriptors":1000}}}}`)},
		"nodes_stats":      {StatusCode: 200, Body: []byte(`{"nodes":{"node-1":{"name":"data-1","roles":["data_hot"],"jvm":{"mem":{"heap_used_in_bytes":880,"heap_max_in_bytes":1000,"heap_used_percent":88},"gc":{"collectors":{"young":{"collection_count":2,"collection_time_in_millis":20},"old":{"collection_count":1,"collection_time_in_millis":100}}}},"os":{"available_processors":4,"cpu":{"percent":50,"load_average":{"1m":2,"5m":1,"15m":1}},"mem":{"total_in_bytes":1000,"free_in_bytes":100,"used_in_bytes":900},"swap":{"total_in_bytes":0,"used_in_bytes":0}},"process":{"cpu":{"percent":40},"open_file_descriptors":10,"max_file_descriptors":1000},"fs":{"total":{"total_in_bytes":1000,"available_in_bytes":100},"data":[{}]},"thread_pool":{"search":{"threads":4,"active":1,"queue":0,"rejected":0,"completed":10}},"breakers":{"parent":{"estimated_size_in_bytes":100,"limit_size_in_bytes":1000,"overhead":1,"tripped":0}},"indices":{"indexing":{"index_total":10,"index_time_in_millis":20,"index_failed":0},"search":{"query_total":10,"query_time_in_millis":20},"segments":{"count":5}}}}}`)},
		"indices":          {StatusCode: 200, Body: []byte(`[{"health":"green","status":"open","index":"logs-000001","uuid":"idx","pri":"1","rep":"0","docs.count":"100","docs.deleted":"20","store.size":"1000","pri.store.size":"1000","creation.date.string":"2026-01-01T00:00:00Z"}]`)},
		"index_settings":   {StatusCode: 200, Body: []byte(`{"logs-000001":{"settings":{"index.number_of_shards":"1","index.number_of_replicas":"0"}}}`)},
		"shards":           {StatusCode: 200, Body: []byte(`[{"index":"logs-000001","shard":"0","prirep":"p","state":"STARTED","docs":"100","store":"1000","ip":"127.0.0.1","node":"data-1"}]`)},
		"pending_tasks":    {StatusCode: 200, Body: []byte(`{"tasks":[]}`)},
		"authenticate":     {StatusCode: 200, Body: []byte(`{"username":"elastic","authentication_type":"realm"}`)},
	}
	collectors := make([]healthmodel.CollectorResult, 0, len(responses))
	for name := range responses {
		collectors = append(collectors, healthmodel.CollectorResult{Name: name, Cost: "LOW", Status: "success", HTTPStatus: 200})
	}
	return collector.ResponseSet{Responses: responses, Collectors: collectors, Requests: len(responses), Bytes: 4096}
}
