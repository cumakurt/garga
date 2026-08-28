package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cumakurt/garga/internal/credential"
	"github.com/cumakurt/garga/internal/model"
	"github.com/cumakurt/garga/internal/target"
	"log/slog"
)

const (
	securityIndexPrefix = ".security"
)

// Engine runs authorized read-only sensitive-data discovery.
type Engine struct {
	options   Options
	secret    *credential.Secret
	userAgent string
	logger    *slog.Logger
	dedupKey  []byte
}

func NewEngine(options Options, secret *credential.Secret, userAgent string, logger *slog.Logger) (*Engine, error) {
	options = options.withDefaults()
	if err := options.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	key, err := newDedupKey()
	if err != nil {
		return nil, err
	}
	return &Engine{options: options, secret: secret, userAgent: userAgent, logger: logger, dedupKey: key}, nil
}

func (engine *Engine) Scan(ctx context.Context, rawTargets []string) (Result, error) {
	started := time.Now().UTC()
	endpoints, err := parseTargets(rawTargets)
	if err != nil {
		return Result{}, err
	}
	if len(endpoints) == 0 {
		return Result{}, fmt.Errorf("at least one secrets target is required")
	}
	scanCtx := ctx
	if engine.options.Timeout > 0 {
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(ctx, engine.options.Timeout)
		defer cancel()
	}

	type job struct {
		raw      string
		endpoint model.Endpoint
	}
	jobs := make(chan job)
	var (
		mu       sync.Mutex
		reports  = make([]TargetReport, 0, len(endpoints))
		findings []Finding
		dedup    = map[string]*Finding{}
	)
	var wg sync.WaitGroup
	workers := engine.options.Concurrency
	if workers > len(endpoints) {
		workers = len(endpoints)
	}
	for index := 0; index < workers; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				report, local := engine.scanTarget(scanCtx, item.raw, item.endpoint)
				mu.Lock()
				reports = append(reports, report)
				for _, finding := range local {
					engine.mergeFinding(dedup, finding)
				}
				mu.Unlock()
			}
		}()
	}
	for _, item := range endpoints {
		select {
		case <-scanCtx.Done():
			close(jobs)
			wg.Wait()
			return Result{}, scanCtx.Err()
		case jobs <- item:
		}
	}
	close(jobs)
	wg.Wait()

	for _, finding := range dedup {
		findings = append(findings, *finding)
	}
	sortFindings(findings)
	sort.Slice(reports, func(i, j int) bool { return reports[i].Target < reports[j].Target })
	finished := time.Now().UTC()
	result := Result{
		SchemaVersion: SchemaVersion,
		Targets:       reports,
		Findings:      findings,
		Summary:       buildSummary(engine.options.scanMode(), reports, findings, started, finished),
	}
	return result, nil
}

func (engine *Engine) mergeFinding(dedup map[string]*Finding, finding Finding) {
	if confidenceRank(finding.Confidence) < confidenceRank(engine.options.MinConfidence) {
		return
	}
	if finding.Occurrences <= 0 {
		finding.Occurrences = 1
	}
	secret := finding.Secret
	if secret == "" {
		secret = finding.MaskedPreview
	}
	keyMaterial := finding.Category + "\x00" + finding.Index + "\x00" + finding.FieldPath
	if finding.CredentialType != "" {
		keyMaterial = finding.Category + "\x00" + finding.Index + "\x00" + finding.CredentialType + "\x00" + finding.MaskedPreview
	}
	key := fingerprintSecret(engine.dedupKey, keyMaterial, secret)
	if existing, ok := dedup[key]; ok {
		existing.Occurrences++
		if severityRank(finding.Severity) > severityRank(existing.Severity) {
			existing.Severity = finding.Severity
		}
		if confidenceRank(finding.Confidence) > confidenceRank(existing.Confidence) {
			existing.Confidence = finding.Confidence
		}
		return
	}
	cloned := finding
	dedup[key] = &cloned
}

func (engine *Engine) scanTarget(ctx context.Context, raw string, endpoint model.Endpoint) (TargetReport, []Finding) {
	report := TargetReport{Target: raw}
	client, err := newESClient(endpoint, engine.secret, engine.options, engine.userAgent)
	if err != nil {
		report.Error = credential.Redact(err.Error(), engine.secret)
		return report, nil
	}
	defer client.http.CloseIdleConnections()

	var root map[string]any
	if err := client.getJSON(ctx, "/", nil, &root); err != nil {
		report.Error = credential.Redact(err.Error(), engine.secret)
		return report, nil
	}
	report.Reachable = true
	report.Cluster = stringField(root, "cluster_name")
	if version, ok := root["version"].(map[string]any); ok {
		report.Version = stringField(version, "number")
	}

	var auth map[string]any
	if err := client.getJSON(ctx, "/_security/_authenticate", nil, &auth); err == nil {
		report.Authenticated = true
		report.AuthIdentity = firstNonEmpty(stringField(auth, "username"), stringField(auth, "full_name"))
	}

	indices, err := engine.listIndices(ctx, client)
	if err != nil {
		report.Error = credential.Redact(err.Error(), engine.secret)
		return report, nil
	}
	aliases := engine.loadAliases(ctx, client)
	_ = engine.loadDataStreams(ctx, client)
	_ = aliases

	var findings []Finding
	budget := engine.options.MaxDocuments
	for _, index := range indices {
		if ctx.Err() != nil {
			break
		}
		if isSecurityIndex(index) {
			findings = append(findings, Finding{
				Target:        raw,
				Cluster:       report.Cluster,
				Index:         index,
				FieldPath:     "*",
				Category:      "exposure.security_index",
				Detector:      "security-index",
				Severity:      SeverityCritical,
				Confidence:    ConfidenceConfirmed,
				MaskedPreview: "Elasticsearch security index is readable by supplied account.",
				Reason:        "Elasticsearch security index is readable by supplied account.",
				Timestamp:     time.Now().UTC(),
				Occurrences:   1,
			})
			continue
		}
		if !engine.includeIndex(index) {
			continue
		}
		indexFindings, sampled, stats := engine.scanIndex(ctx, client, raw, report.Cluster, index, &budget)
		report.DocumentsSampled += sampled
		report.DocumentsExamined += sampled
		report.FieldsExamined += stats.fields
		report.BytesExamined += stats.bytes
		report.IndicesInspected++
		findings = append(findings, indexFindings...)
		if budget <= 0 {
			break
		}
	}
	return report, findings
}

func (engine *Engine) listIndices(ctx context.Context, client *esClient) ([]string, error) {
	query := url.Values{}
	query.Set("format", "json")
	query.Set("h", "index,status")
	var rows []struct {
		Index  string `json:"index"`
		Status string `json:"status"`
	}
	if err := client.getJSON(ctx, "/_cat/indices", query, &rows); err != nil {
		return nil, err
	}
	var names []string
	for _, row := range rows {
		name := strings.TrimSpace(row.Index)
		if name == "" || !validIndexName(name) {
			continue
		}
		if !strings.EqualFold(row.Status, "open") && row.Status != "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (engine *Engine) includeIndex(name string) bool {
	if !engine.options.IncludeSystemIndices && strings.HasPrefix(name, ".") {
		return false
	}
	if len(engine.options.Indices) > 0 && !matchAny(name, engine.options.Indices) {
		return false
	}
	if matchAny(name, engine.options.ExcludeIndices) {
		return false
	}
	return true
}

func (engine *Engine) loadAliases(ctx context.Context, client *esClient) map[string][]string {
	var raw map[string]any
	if err := client.getJSON(ctx, "/_alias", nil, &raw); err != nil {
		engine.logger.DebugContext(ctx, "secrets alias listing failed", slog.String("error", credential.Redact(err.Error(), engine.secret)))
		return nil
	}
	aliases := make(map[string][]string)
	for index, body := range raw {
		object, _ := body.(map[string]any)
		aliasMap, _ := object["aliases"].(map[string]any)
		for alias := range aliasMap {
			aliases[alias] = append(aliases[alias], index)
		}
	}
	return aliases
}

func (engine *Engine) loadDataStreams(ctx context.Context, client *esClient) []string {
	var raw map[string]any
	if err := client.getJSON(ctx, "/_data_stream", nil, &raw); err != nil {
		engine.logger.DebugContext(ctx, "secrets data stream listing failed", slog.String("error", credential.Redact(err.Error(), engine.secret)))
		return nil
	}
	streams, _ := raw["data_streams"].([]any)
	var names []string
	for _, item := range streams {
		object, _ := item.(map[string]any)
		if name := stringField(object, "name"); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func (engine *Engine) scanIndex(ctx context.Context, client *esClient, targetURL, cluster, index string, budget *int) ([]Finding, int, walkStats) {
	limits := engine.options.walkLimits()
	var mapping map[string]any
	mappingPath := "/" + url.PathEscape(index) + "/_mapping"
	fields := []FieldSemantics{}
	if err := client.getJSON(ctx, mappingPath, nil, &mapping); err == nil {
		if wrapped, ok := mapping[index].(map[string]any); ok {
			fields = mappingFields(wrapped["mappings"], "", 0, limits)
		} else {
			fields = mappingFields(mapping, "", 0, limits)
		}
	} else {
		engine.logger.DebugContext(ctx, "secrets mapping fetch failed", slog.String("index", index), slog.String("error", credential.Redact(err.Error(), engine.secret)))
	}

	maxFields := engine.options.MaxSourceFields
	if maxFields <= 0 {
		maxFields = DefaultMaxSourceFields
	}
	includes := sourceIncludes(fields, maxFields, engine.options.ScanGenericFields)
	sampleSize := engine.options.SampleSize
	if *budget < sampleSize {
		sampleSize = *budget
	}
	if sampleSize <= 0 {
		return nil, 0, walkStats{}
	}
	documents, err := engine.sampleDocuments(ctx, client, index, includes, sampleSize)
	if err != nil {
		engine.logger.WarnContext(ctx, "secrets sampling failed", slog.String("index", index), slog.String("error", credential.Redact(err.Error(), engine.secret)))
		return nil, 0, walkStats{}
	}

	var findings []Finding
	var stats walkStats
	now := time.Now().UTC()
	for _, document := range documents {
		if ctx.Err() != nil {
			break
		}
		walked := walkDocumentStats(document.Source, limits)
		document.Source = nil
		stats.fields += walked.stats.fields
		stats.bytes += walked.stats.bytes
		for _, item := range walked.hits {
			fieldPath := item.FieldPath
			if fieldPath == "" {
				fieldPath = itemPathFromHit(item)
			}
			finding := Finding{
				Target:         targetURL,
				Cluster:        cluster,
				Index:          index,
				DocumentID:     document.ID,
				FieldPath:      firstNonEmpty(fieldPath, "document"),
				ObjectPath:     item.ObjectPath,
				RelatedFields:  item.RelatedFields,
				CredentialType: item.CredentialType,
				Category:       item.Category,
				Detector:       item.Detector,
				Severity:       item.Severity,
				Confidence:     item.Confidence,
				MaskedPreview:  item.Masked,
				MaskedValues:   item.MaskedValues,
				Reason:         item.Reason,
				Timestamp:      now,
				Occurrences:    1,
			}
			if !item.Suppress {
				finding.Secret = item.Raw
			}
			findings = append(findings, finding)
		}
	}
	*budget -= len(documents)
	return findings, len(documents), stats
}

type sampledDocument struct {
	ID     string
	Source map[string]any
	sort   []any
}

func (engine *Engine) sampleDocuments(ctx context.Context, client *esClient, index string, includes []string, limit int) ([]sampledDocument, error) {
	batch := engine.options.SearchBatch
	if batch > limit {
		batch = limit
	}
	var (
		documents []sampledDocument
		sortAfter []any
	)
	for len(documents) < limit {
		remaining := limit - len(documents)
		size := batch
		if size > remaining {
			size = remaining
		}
		body, err := searchBody(size, includes, sortAfter)
		if err != nil {
			return documents, err
		}
		var response searchResponse
		if err := client.postSearch(ctx, index, body, &response); err != nil {
			return documents, err
		}
		if len(response.Hits.Hits) == 0 {
			break
		}
		for _, hit := range response.Hits.Hits {
			documents = append(documents, sampledDocument{ID: hit.ID, Source: hit.Source, sort: hit.Sort})
		}
		last := response.Hits.Hits[len(response.Hits.Hits)-1]
		sortAfter = last.Sort
		if len(sortAfter) == 0 {
			break
		}
		if len(response.Hits.Hits) < size {
			break
		}
	}
	return documents, nil
}

type searchResponse struct {
	Hits struct {
		Hits []struct {
			ID     string         `json:"_id"`
			Source map[string]any `json:"_source"`
			Sort   []any          `json:"sort"`
		} `json:"hits"`
	} `json:"hits"`
}

func searchBody(size int, includes []string, searchAfter []any) ([]byte, error) {
	request := map[string]any{
		"size":             size,
		"track_total_hits": false,
		// _id fielddata is disabled on Elasticsearch 8+/9; _doc enables search_after without a PIT.
		"sort": []any{"_doc"},
	}
	if len(includes) > 0 {
		request["_source"] = includes
	}
	if len(searchAfter) > 0 {
		request["search_after"] = searchAfter
	}
	return json.Marshal(request)
}

func itemPathFromHit(item hit) string {
	if item.FieldPath != "" {
		return item.FieldPath
	}
	return ""
}

func parseTargets(rawTargets []string) ([]struct {
	raw      string
	endpoint model.Endpoint
}, error) {
	type item struct {
		raw      string
		endpoint model.Endpoint
	}
	seen := make(map[string]struct{})
	var out []item
	for _, raw := range rawTargets {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parsed, err := target.Parse(raw, "cli")
		if err != nil {
			return nil, fmt.Errorf("invalid secrets target %q", raw)
		}
		endpoint, err := target.Endpoint(parsed)
		if err != nil {
			return nil, fmt.Errorf("invalid secrets target %q", raw)
		}
		canonical, err := endpoint.URL()
		if err != nil {
			return nil, err
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, item{raw: canonical, endpoint: endpoint})
	}
	converted := make([]struct {
		raw      string
		endpoint model.Endpoint
	}, len(out))
	for index, item := range out {
		converted[index] = struct {
			raw      string
			endpoint model.Endpoint
		}{raw: item.raw, endpoint: item.endpoint}
	}
	return converted, nil
}

func matchAny(name string, patterns []string) bool {
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.EqualFold(name, pattern) {
			return true
		}
		if ok, _ := path.Match(pattern, name); ok {
			return true
		}
	}
	return false
}

func isSecurityIndex(name string) bool {
	return name == ".security" || strings.HasPrefix(name, securityIndexPrefix)
}

func stringField(object map[string]any, key string) string {
	if object == nil {
		return ""
	}
	value, _ := object[key].(string)
	return value
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		if findings[i].Index != findings[j].Index {
			return findings[i].Index < findings[j].Index
		}
		if findings[i].FieldPath != findings[j].FieldPath {
			return findings[i].FieldPath < findings[j].FieldPath
		}
		return findings[i].Category < findings[j].Category
	})
}

func buildSummary(mode ScanMode, reports []TargetReport, findings []Finding, started, finished time.Time) Summary {
	summary := Summary{
		ScanMode:          mode,
		TargetsScanned:    len(reports),
		SeverityCounts:    map[string]int{},
		CategoryCounts:    map[string]int{},
		CorrelationCounts: map[string]int{},
		StartedAt:         started,
		FinishedAt:        finished,
		ScanDurationMS:    scanDurationMS(started, finished),
	}
	indexCounts := map[string]int{}
	for _, report := range reports {
		if report.Reachable {
			summary.ReachableTargets++
		}
		if report.Error != "" {
			summary.PartialFailures++
		}
		summary.IndicesInspected += report.IndicesInspected
		summary.DocumentsSampled += report.DocumentsSampled
		summary.DocumentsExamined += report.DocumentsExamined
		summary.FieldsExamined += report.FieldsExamined
		summary.BytesExamined += report.BytesExamined
	}
	if summary.DocumentsExamined == 0 {
		summary.DocumentsExamined = summary.DocumentsSampled
	}
	for _, finding := range findings {
		summary.Findings++
		summary.SeverityCounts[string(finding.Severity)]++
		summary.CategoryCounts[prettyCategory(finding.Category)]++
		indexCounts[finding.Index]++
		if finding.CredentialType != "" || finding.Detector == "credential-pair" {
			summary.CorrelatedFindings++
			label := correlationSummaryLabel(finding.CredentialType, finding.Category)
			summary.CorrelationCounts[label]++
		} else {
			summary.FieldFindings++
		}
	}
	type ranked struct {
		index string
		count int
	}
	var top []ranked
	for index, count := range indexCounts {
		top = append(top, ranked{index: index, count: count})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].count == top[j].count {
			return top[i].index < top[j].index
		}
		return top[i].count > top[j].count
	})
	if len(top) > 10 {
		top = top[:10]
	}
	for _, item := range top {
		summary.TopIndices = append(summary.TopIndices, IndexCount{Index: item.index, Count: item.count})
	}
	return summary
}

func prettyCategory(category string) string {
	switch category {
	case "credential.password":
		return "Passwords"
	case "credential.pair":
		return "Credential pairs"
	case "credential.client":
		return "Client ID + Client Secret"
	case "credential.access_key_pair":
		return "Access Key + Secret Key"
	case "credential.api_pair":
		return "API Key + API Secret"
	case "credential.token_pair":
		return "Token pairs"
	case "credential.database":
		return "Database credentials"
	case "credential.api_key":
		return "API keys"
	case "credential.access_token":
		return "Access tokens"
	case "credential.private_key":
		return "Private keys"
	case "credential.connection_string":
		return "Database connection strings"
	case "credential.http.basic":
		return "HTTP Basic credentials"
	case "credential.http.bearer":
		return "HTTP Bearer credentials"
	case "credential.password_hash":
		return "Password hashes"
	case "possible-secret":
		return "Possible secrets"
	default:
		return category
	}
}

func correlationSummaryLabel(credentialType, category string) string {
	switch credentialType {
	case "username_password":
		return "Username + Password"
	case "client_credentials":
		return "Client ID + Client Secret"
	case "access_key_pair":
		return "Access Key + Secret Key"
	case "database_credentials":
		return "Database Credentials"
	case "api_credentials":
		return "API Key + API Secret"
	case "token_pair", "username_token", "client_token":
		return "Token Pairs"
	case "smtp_credentials":
		return "SMTP Credentials"
	case "ldap_credentials":
		return "LDAP Credentials"
	case "connection_string":
		return "Connection Strings"
	case "http_basic":
		return "HTTP Basic"
	case "http_bearer":
		return "HTTP Bearer"
	case "key_secret":
		return "Key + Secret"
	}
	return prettyCategory(category)
}
