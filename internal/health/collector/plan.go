package collector

import "net/url"

type Cost string

const (
	CostLow    Cost = "LOW"
	CostMedium Cost = "MEDIUM"
	CostHigh   Cost = "HIGH"
)

type requestSpec struct {
	Name     string
	Path     string
	Query    url.Values
	Cost     Cost
	Deep     bool
	MinMajor int
	MaxMajor int
}

func requestPlan() []requestSpec {
	return []requestSpec{
		{Name: "cluster_health", Path: "/_cluster/health", Cost: CostLow},
		{Name: "cluster_stats", Path: "/_cluster/stats", Cost: CostLow},
		{Name: "cluster_settings", Path: "/_cluster/settings", Query: values("include_defaults", "true", "flat_settings", "true"), Cost: CostLow},
		{Name: "nodes_info", Path: "/_nodes/_all/os,process,jvm", Cost: CostLow},
		{Name: "nodes_stats", Path: "/_nodes/stats/jvm,os,process,fs,thread_pool,breaker,indices,indexing_pressure", Cost: CostMedium, MinMajor: 7},
		{Name: "indices", Path: "/_cat/indices", Query: values("format", "json", "bytes", "b", "h", "health,status,index,uuid,pri,rep,docs.count,docs.deleted,store.size,pri.store.size,creation.date.string"), Cost: CostMedium},
		{Name: "shards", Path: "/_cat/shards", Query: values("format", "json", "bytes", "b", "h", "index,shard,prirep,state,docs,store,ip,node,unassigned.reason,unassigned.at"), Cost: CostMedium},
		{Name: "index_settings", Path: "/_settings", Query: values("flat_settings", "true", "filter_path", "*.settings.index.number_of_shards,*.settings.index.number_of_replicas,*.settings.index.refresh_interval,*.settings.index.translog.*,*.settings.index.routing.*,*.settings.index.blocks.*,*.settings.index.lifecycle.*,*.settings.index.creation_date,*.settings.index.hidden"), Cost: CostMedium},
		{Name: "pending_tasks", Path: "/_cluster/pending_tasks", Cost: CostLow},
		{Name: "authenticate", Path: "/_security/_authenticate", Cost: CostLow, MinMajor: 7},
		{Name: "nodes_settings", Path: "/_nodes/settings", Query: values("flat_settings", "true", "filter_path", "nodes.*.settings.xpack.security.*"), Cost: CostMedium, Deep: true},
		{Name: "ilm", Path: "/_ilm/explain", Cost: CostHigh, Deep: true, MinMajor: 7},
		{Name: "data_streams", Path: "/_data_stream", Cost: CostMedium, Deep: true, MinMajor: 7},
		{Name: "tasks", Path: "/_tasks", Query: values("detailed", "false", "group_by", "none"), Cost: CostHigh, Deep: true},
		{Name: "snapshot_repositories", Path: "/_snapshot/_all", Cost: CostMedium, Deep: true},
	}
}

func values(pairs ...string) url.Values {
	result := make(url.Values, len(pairs)/2)
	for index := 0; index+1 < len(pairs); index += 2 {
		result.Set(pairs[index], pairs[index+1])
	}
	return result
}
