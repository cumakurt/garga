package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/cumakurt/garga/internal/credential"
	healthmodel "github.com/cumakurt/garga/internal/health/model"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/transport"
)

const (
	maxSnapshotRepositories = 20
	maxSnapshotHistory      = 20
	minimumHealthVersion    = "7.17.0"
	maximumHealthVersion    = "9.999.999"
)

type Options struct {
	Endpoint    model.Endpoint
	Client      *transport.Client
	Secret      *credential.Secret
	Deep        bool
	Concurrency int
	Rate        float64
	Retries     int
}

type ResponseSet struct {
	Responses  map[string]transport.Response
	Collectors []healthmodel.CollectorResult
	Requests   int
	Bytes      int64
	Failed     int
	Retried    int
}

type Collector struct {
	client      *client
	deep        bool
	concurrency int
}

func New(options Options) (*Collector, error) {
	if options.Concurrency < 1 || options.Concurrency > 32 {
		return nil, wrap(ErrorConfiguration, errors.New("health concurrency is invalid"))
	}
	requestClient, err := newClient(options.Client, options.Endpoint, options.Secret, options.Rate, options.Retries)
	if err != nil {
		return nil, err
	}
	return &Collector{client: requestClient, deep: options.Deep, concurrency: options.Concurrency}, nil
}

func (collector *Collector) Collect(ctx context.Context) (ResponseSet, error) {
	if ctx == nil {
		return ResponseSet{}, wrap(ErrorConfiguration, errors.New("context is required"))
	}
	rootSpec := requestSpec{Name: "root", Cost: CostLow}
	root, err := collector.client.get(ctx, rootSpec)
	if err != nil {
		return ResponseSet{}, wrap(ErrorConnection, err)
	}
	if root.StatusCode == http.StatusUnauthorized || root.StatusCode == http.StatusForbidden {
		return ResponseSet{}, wrap(ErrorAuthentication, fmt.Errorf("root endpoint returned HTTP %d", root.StatusCode))
	}
	if root.StatusCode < 200 || root.StatusCode > 299 {
		return ResponseSet{}, wrap(ErrorProduct, fmt.Errorf("root endpoint returned HTTP %d", root.StatusCode))
	}
	version, elasticsearch := rootVersion(root.Body)
	if !elasticsearch || !supportedHealthVersion(version) {
		return ResponseSet{}, wrap(ErrorProduct, errors.New("root response is not a supported Elasticsearch version"))
	}
	major := healthmodel.Version{Number: version}.Major()

	set := ResponseSet{Responses: map[string]transport.Response{"root": root}}
	set.Collectors = append(set.Collectors, healthmodel.CollectorResult{Name: "root", Cost: string(CostLow), Status: "success", HTTPStatus: root.StatusCode})
	var plan []requestSpec
	for _, spec := range requestPlan() {
		if spec.Deep && !collector.deep {
			set.Collectors = append(set.Collectors, healthmodel.CollectorResult{Name: spec.Name, Cost: string(spec.Cost), Status: "skipped", Reason: "deep_scan_disabled"})
			continue
		}
		if spec.MinMajor > 0 && major < spec.MinMajor || spec.MaxMajor > 0 && major > spec.MaxMajor {
			set.Collectors = append(set.Collectors, healthmodel.CollectorResult{Name: spec.Name, Cost: string(spec.Cost), Status: "skipped", Reason: "unsupported_version"})
			continue
		}
		plan = append(plan, spec)
	}
	collector.collectPlan(ctx, plan, &set)
	if err := ctx.Err(); err != nil {
		return set, err
	}
	collector.collectAllocationExplain(ctx, &set)
	if collector.deep {
		collector.collectSnapshots(ctx, &set)
	}
	requests, bytes, failed, retried := collector.client.telemetry()
	set.Requests, set.Bytes, set.Failed, set.Retried = requests, bytes, failed, retried
	sort.SliceStable(set.Collectors, func(left, right int) bool { return set.Collectors[left].Name < set.Collectors[right].Name })
	return set, nil
}

func (collector *Collector) collectPlan(ctx context.Context, plan []requestSpec, set *ResponseSet) {
	if len(plan) == 0 {
		return
	}
	jobs := make(chan requestSpec)
	results := make(chan collectionResult, len(plan))
	var workers sync.WaitGroup
	workerCount := collector.concurrency
	if workerCount > len(plan) {
		workerCount = len(plan)
	}
	for index := 0; index < workerCount; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for spec := range jobs {
				response, err := collector.client.get(ctx, spec)
				results <- collectionResult{spec: spec, response: response, err: err}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, spec := range plan {
			select {
			case <-ctx.Done():
				return
			case jobs <- spec:
			}
		}
	}()
	workers.Wait()
	close(results)
	completed := make(map[string]struct{}, len(plan))
	for result := range results {
		collector.record(set, result.spec, result.response, result.err)
		completed[result.spec.Name] = struct{}{}
	}
	for _, spec := range plan {
		if _, done := completed[spec.Name]; done {
			continue
		}
		set.Collectors = append(set.Collectors, healthmodel.CollectorResult{Name: spec.Name, Cost: string(spec.Cost), Status: "skipped", Reason: "canceled"})
	}
}

type collectionResult struct {
	spec     requestSpec
	response transport.Response
	err      error
}

func (collector *Collector) record(set *ResponseSet, spec requestSpec, response transport.Response, err error) {
	result := healthmodel.CollectorResult{Name: spec.Name, Cost: string(spec.Cost), HTTPStatus: response.StatusCode}
	switch {
	case err != nil:
		result.Status = "failed"
		result.Reason = errorReason(err)
	case response.StatusCode >= 200 && response.StatusCode <= 299:
		result.Status = "success"
		set.Responses[spec.Name] = response
	case response.StatusCode == http.StatusUnauthorized:
		result.Status = "failed"
		result.Reason = "authentication_required"
	case response.StatusCode == http.StatusForbidden:
		result.Status = "skipped"
		result.Reason = "insufficient_privileges"
	case response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusMethodNotAllowed:
		result.Status = "skipped"
		result.Reason = "api_unavailable"
	default:
		result.Status = "failed"
		result.Reason = "unexpected_http_status"
	}
	set.Collectors = append(set.Collectors, result)
}

func (collector *Collector) collectAllocationExplain(ctx context.Context, set *ResponseSet) {
	response, ok := set.Responses["cluster_health"]
	if !ok {
		set.Collectors = append(set.Collectors, healthmodel.CollectorResult{Name: "allocation_explain", Cost: string(CostMedium), Status: "skipped", Reason: "cluster_health_unavailable"})
		return
	}
	var health struct {
		Unassigned int `json:"unassigned_shards"`
	}
	if json.Unmarshal(response.Body, &health) != nil || health.Unassigned == 0 {
		set.Collectors = append(set.Collectors, healthmodel.CollectorResult{Name: "allocation_explain", Cost: string(CostMedium), Status: "skipped", Reason: "no_unassigned_shards"})
		return
	}
	spec := requestSpec{Name: "allocation_explain", Path: "/_cluster/allocation/explain", Cost: CostMedium}
	allocation, err := collector.client.get(ctx, spec)
	collector.record(set, spec, allocation, err)
}

func (collector *Collector) collectSnapshots(ctx context.Context, set *ResponseSet) {
	response, ok := set.Responses["snapshot_repositories"]
	if !ok {
		return
	}
	var repositories map[string]json.RawMessage
	if json.Unmarshal(response.Body, &repositories) != nil {
		set.Collectors = append(set.Collectors, healthmodel.CollectorResult{Name: "snapshots", Cost: string(CostHigh), Status: "skipped", Reason: "repository_response_invalid"})
		return
	}
	names := make([]string, 0, len(repositories))
	for name := range repositories {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > maxSnapshotRepositories {
		set.Collectors = append(set.Collectors, healthmodel.CollectorResult{Name: "snapshots_limit", Cost: string(CostHigh), Status: "skipped", Reason: "repository_limit_reached"})
		names = names[:maxSnapshotRepositories]
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return
		}
		if !safeRepositoryName(name) {
			set.Collectors = append(set.Collectors, healthmodel.CollectorResult{Name: "snapshots", Cost: string(CostHigh), Status: "skipped", Reason: "repository_name_not_path_safe"})
			continue
		}
		spec := requestSpec{
			Name:  "snapshots:" + name,
			Path:  "/_snapshot/" + name + "/_all",
			Query: values("ignore_unavailable", "true", "verbose", "false", "size", fmt.Sprintf("%d", maxSnapshotHistory), "order", "desc", "sort", "start_time"),
			Cost:  CostHigh,
		}
		snapshots, err := collector.client.get(ctx, spec)
		collector.record(set, spec, snapshots, err)
	}
}

func safeRepositoryName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '-', '_', '.':
			continue
		default:
			return false
		}
	}
	return true
}

func rootVersion(body []byte) (string, bool) {
	var root struct {
		Version struct {
			Number       string `json:"number"`
			Distribution string `json:"distribution"`
		} `json:"version"`
		Tagline string `json:"tagline"`
	}
	if json.Unmarshal(body, &root) != nil || root.Version.Number == "" {
		return "", false
	}
	if strings.EqualFold(root.Version.Distribution, "opensearch") || strings.Contains(strings.ToLower(root.Tagline), "opensearch") {
		return "", false
	}
	return root.Version.Number, true
}

func supportedHealthVersion(version string) bool {
	return healthmodel.VersionConstraint{Min: minimumHealthVersion, Max: maximumHealthVersion}.Supports(version)
}

func errorReason(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if kind, ok := transport.KindOf(err); ok {
		return string(kind)
	}
	return "request_failed"
}
