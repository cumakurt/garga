package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
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
	securityProbeBody   = `{"size":0,"track_total_hits":false,"_source":false}`
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

func (engine *Engine) Scan(ctx context.Context, rawTargets []string) (ScanReport, error) {
	started := time.Now().UTC()
	endpoints, err := parseTargets(rawTargets)
	if err != nil {
		return ScanReport{}, err
	}
	if len(endpoints) == 0 {
		return ScanReport{}, fmt.Errorf("at least one secrets target is required")
	}
	scanCtx := ctx
	if engine.options.Timeout > 0 {
		var cancel context.CancelFunc
		scanCtx, cancel = context.WithTimeout(ctx, engine.options.Timeout)
		defer cancel()
	}

	type job struct {
		index    int
		raw      string
		endpoint model.Endpoint
	}
	type targetResult struct {
		report   TargetReport
		findings []Finding
	}
	jobs := make(chan job)
	targetResults := make([]targetResult, len(endpoints))
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
				report, findings := engine.scanTarget(scanCtx, item.raw, item.endpoint)
				targetResults[item.index] = targetResult{report: report, findings: findings}
			}
		}()
	}
	for index, item := range endpoints {
		select {
		case <-scanCtx.Done():
			close(jobs)
			wg.Wait()
			return ScanReport{}, scanCtx.Err()
		case jobs <- job{index: index, raw: item.raw, endpoint: item.endpoint}:
		}
	}
	close(jobs)
	wg.Wait()
	if err := scanCtx.Err(); err != nil {
		return ScanReport{}, err
	}

	reports := make([]TargetReport, 0, len(targetResults))
	dedup := make(map[string]*Finding)
	for _, targetResult := range targetResults {
		report := targetResult.report
		for _, finding := range targetResult.findings {
			if engine.mergeFinding(dedup, finding) {
				report.FindingsTruncated = true
			}
		}
		if report.FindingsTruncated && report.Error == "" {
			report.Error = fmt.Sprintf("finding limit of %d reached", MaxReportFindings)
		}
		reports = append(reports, report)
	}
	findings := make([]Finding, 0, len(dedup))
	for _, finding := range dedup {
		findings = append(findings, *finding)
	}
	sortFindings(findings)
	finalizeFindings(findings)
	sort.Slice(reports, func(i, j int) bool { return reports[i].Target < reports[j].Target })
	finished := time.Now().UTC()
	result := ScanReport{
		SchemaVersion: SchemaVersion,
		Targets:       reports,
		Findings:      findings,
		Summary:       buildSummary(engine.options.scanMode(), reports, findings, started, finished),
	}
	if err := ValidateResult(result); err != nil {
		return ScanReport{}, fmt.Errorf("validate secrets report: %w", err)
	}
	return result, nil
}

func (engine *Engine) mergeFinding(dedup map[string]*Finding, finding Finding) bool {
	if confidenceRank(finding.Confidence) < confidenceRank(engine.options.MinConfidence) {
		return false
	}
	if finding.Occurrences <= 0 {
		finding.Occurrences = 1
	}
	dedupFingerprint := finding.dedupFingerprint
	if dedupFingerprint == "" {
		dedupFingerprint = fingerprintSecret(engine.dedupKey, finding.Category, finding.MaskedPreview)
	}
	keyMaterial := finding.Target + "\x00" + finding.Cluster + "\x00" + finding.Category + "\x00" + finding.Index + "\x00" + finding.FieldPath
	if finding.CredentialType != "" {
		keyMaterial = finding.Target + "\x00" + finding.Cluster + "\x00" + finding.Category + "\x00" + finding.Index + "\x00" + finding.CredentialType + "\x00" + finding.MaskedPreview
	}
	key := fingerprintSecret(engine.dedupKey, keyMaterial, dedupFingerprint)
	if existing, ok := dedup[key]; ok {
		existing.Occurrences += finding.Occurrences
		if severityRank(finding.Severity) > severityRank(existing.Severity) {
			existing.Severity = finding.Severity
		}
		if confidenceRank(finding.Confidence) > confidenceRank(existing.Confidence) {
			existing.Confidence = finding.Confidence
		}
		return false
	}
	if len(dedup) >= MaxReportFindings {
		return true
	}
	cloned := finding
	cloned.dedupFingerprint = ""
	dedup[key] = &cloned
	return false
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
		if responseWasReceived(err) {
			report.Reachable = true
		}
		report.Error = credential.Redact(err.Error(), engine.secret)
		return report, nil
	}
	report.Reachable = true
	if err := validateElasticsearchRoot(root); err != nil {
		report.Error = err.Error()
		return report, nil
	}
	report.Cluster = stringField(root, "cluster_name")
	if version, ok := root["version"].(map[string]any); ok {
		report.Version = stringField(version, "number")
	}

	var auth map[string]any
	if err := client.getJSON(ctx, "/_security/_authenticate", nil, &auth); err == nil {
		report.Authenticated = true
		report.AuthIdentity = credential.Redact(firstNonEmpty(stringField(auth, "username"), stringField(auth, "full_name")), engine.secret)
	}

	indices, err := engine.listIndices(ctx, client)
	if err != nil {
		report.Error = credential.Redact(err.Error(), engine.secret)
		return report, nil
	}
	aliases := engine.loadAliases(ctx, client)
	dataStreams := engine.loadDataStreams(ctx, client)
	indices = engine.expandCatalogIndices(indices, aliases, dataStreams)

	var findings []Finding
	budget := engine.options.MaxDocuments
	for _, index := range indices {
		if ctx.Err() != nil {
			break
		}
		if !engine.includeIndex(index) {
			continue
		}
		if isSecurityIndex(index) {
			var probe searchResponse
			if err := client.postSearch(ctx, index, []byte(securityProbeBody), &probe); err != nil {
				engine.logger.DebugContext(ctx, "secrets security index read probe denied", slog.String("index", index), slog.String("error", credential.Redact(err.Error(), engine.secret)))
				continue
			}
			report.IndicesInspected++
			findings = append(findings, Finding{
				Target:        raw,
				Cluster:       report.Cluster,
				Index:         index,
				FieldPath:     "*",
				Category:      "exposure.security_index",
				Detector:      "security-index",
				Severity:      SeverityCritical,
				Confidence:    ConfidenceConfirmed,
				MaskedPreview: "Elasticsearch security index read probe succeeded without retrieving documents.",
				Reason:        "A zero-document, source-disabled search confirmed that the supplied identity can read the Elasticsearch security index.",
				Timestamp:     time.Now().UTC(),
				Occurrences:   1,
			})
			continue
		}
		indexFindings, sampled, stats, truncated, indexErr := engine.scanIndex(ctx, client, raw, report.Cluster, index, &budget)
		if indexErr != nil {
			if report.Error == "" {
				report.Error = credential.Redact(indexErr.Error(), engine.secret)
			}
			engine.logger.WarnContext(ctx, "secrets index scan failed", slog.String("index", index), slog.String("error", credential.Redact(indexErr.Error(), engine.secret)))
			continue
		}
		report.DocumentsSampled += sampled
		report.DocumentsExamined += sampled
		report.FieldsExamined += stats.fields
		report.BytesExamined += stats.bytes
		report.IndicesInspected++
		remainingFindings := MaxReportFindings - len(findings)
		if len(indexFindings) > remainingFindings {
			indexFindings = indexFindings[:remainingFindings]
			truncated = true
		}
		findings = append(findings, indexFindings...)
		if truncated || len(findings) >= MaxReportFindings {
			report.FindingsTruncated = true
			if report.Error == "" {
				report.Error = fmt.Sprintf("finding limit of %d reached", MaxReportFindings)
			}
			break
		}
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

type dataStreamIndices struct {
	backing []string
	hidden  bool
}

func (engine *Engine) loadDataStreams(ctx context.Context, client *esClient) map[string]dataStreamIndices {
	var raw map[string]any
	if err := client.getJSON(ctx, "/_data_stream", nil, &raw); err != nil {
		engine.logger.DebugContext(ctx, "secrets data stream listing failed", slog.String("error", credential.Redact(err.Error(), engine.secret)))
		return nil
	}
	streams, _ := raw["data_streams"].([]any)
	catalog := make(map[string]dataStreamIndices)
	for _, item := range streams {
		object, _ := item.(map[string]any)
		name := stringField(object, "name")
		if name == "" || !validIndexName(name) {
			continue
		}
		stream := dataStreamIndices{}
		stream.hidden, _ = object["hidden"].(bool)
		indices, _ := object["indices"].([]any)
		for _, rawIndex := range indices {
			indexObject, _ := rawIndex.(map[string]any)
			indexName := stringField(indexObject, "index_name")
			if validIndexName(indexName) {
				stream.backing = append(stream.backing, indexName)
			}
		}
		sort.Strings(stream.backing)
		catalog[name] = stream
	}
	return catalog
}

func (engine *Engine) expandCatalogIndices(concrete []string, aliases map[string][]string, streams map[string]dataStreamIndices) []string {
	selected := make(map[string]struct{}, len(concrete))
	add := func(index string, resolved, dataStreamBacking bool) {
		if !validIndexName(index) || matchAny(index, engine.options.ExcludeIndices) {
			return
		}
		if !resolved {
			if !engine.includeIndex(index) {
				return
			}
		} else if !dataStreamBacking && !engine.options.IncludeSystemIndices && strings.HasPrefix(index, ".") {
			return
		}
		selected[index] = struct{}{}
	}
	for _, index := range concrete {
		add(index, false, false)
	}
	if len(engine.options.Indices) > 0 {
		for alias, backing := range aliases {
			if !matchAny(alias, engine.options.Indices) || matchAny(alias, engine.options.ExcludeIndices) {
				continue
			}
			for _, index := range backing {
				add(index, true, false)
			}
		}
	}
	for name, stream := range streams {
		if stream.hidden && !engine.options.IncludeSystemIndices {
			continue
		}
		if len(engine.options.Indices) > 0 && !matchAny(name, engine.options.Indices) {
			continue
		}
		if matchAny(name, engine.options.ExcludeIndices) {
			continue
		}
		for _, index := range stream.backing {
			add(index, true, true)
		}
	}
	indices := make([]string, 0, len(selected))
	for index := range selected {
		indices = append(indices, index)
	}
	sort.Strings(indices)
	return indices
}

func (engine *Engine) scanIndex(ctx context.Context, client *esClient, targetURL, cluster, index string, budget *int) ([]Finding, int, walkStats, bool, error) {
	limits := engine.options.walkLimits()
	var mapping map[string]any
	mappingPath := "/" + url.PathEscape(index) + "/_mapping"
	if err := client.getJSON(ctx, mappingPath, nil, &mapping); err != nil {
		return nil, 0, walkStats{}, false, fmt.Errorf("read mapping for index %q: %w", index, err)
	}
	var fields []FieldSemantics
	if wrapped, ok := mapping[index].(map[string]any); ok {
		fields = mappingFields(wrapped["mappings"], "", 0, limits)
	} else {
		fields = mappingFields(mapping, "", 0, limits)
	}

	maxFields := engine.options.MaxSourceFields
	if maxFields <= 0 {
		maxFields = DefaultMaxSourceFields
	}
	includes := sourceIncludes(fields, maxFields, engine.options.ScanGenericFields)
	if len(includes) == 0 {
		return nil, 0, walkStats{}, false, nil
	}
	sampleSize := engine.options.SampleSize
	if *budget < sampleSize {
		sampleSize = *budget
	}
	if sampleSize <= 0 {
		return nil, 0, walkStats{}, false, nil
	}
	documents, err := engine.sampleDocuments(ctx, client, index, includes, sampleSize)
	if err != nil {
		return nil, 0, walkStats{}, false, fmt.Errorf("sample index %q: %w", index, err)
	}

	var findings []Finding
	var stats walkStats
	processed := 0
	truncated := false
	now := time.Now().UTC()
	for docIndex := range documents {
		if ctx.Err() != nil {
			break
		}
		walked := walkDocumentStats(documents[docIndex].Source, limits)
		documents[docIndex].Source = nil
		stats.fields += walked.stats.fields
		stats.bytes += walked.stats.bytes
		processed++
		for _, item := range walked.hits {
			if len(findings) >= MaxReportFindings {
				truncated = true
				break
			}
			fieldPath := item.FieldPath
			if fieldPath == "" {
				fieldPath = itemPathFromHit(item)
			}
			finding := Finding{
				Target:         targetURL,
				Cluster:        cluster,
				Index:          index,
				DocumentID:     documents[docIndex].ID,
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
			fingerprintValue := item.Raw
			if fingerprintValue == "" {
				fingerprintValue = item.Masked
			}
			finding.dedupFingerprint = fingerprintSecret(engine.dedupKey, item.Category, fingerprintValue)
			findings = append(findings, finding)
		}
		if truncated {
			break
		}
	}
	*budget -= processed
	return findings, processed, stats, truncated, nil
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
		if response.Shards.Failed > 0 {
			return documents, fmt.Errorf("search response reported %d failed shards", response.Shards.Failed)
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
	Shards struct {
		Failed int `json:"failed"`
	} `json:"_shards"`
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
	sort.Slice(converted, func(i, j int) bool { return converted[i].raw < converted[j].raw })
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

func validateElasticsearchRoot(root map[string]any) error {
	clusterName := strings.TrimSpace(stringField(root, "cluster_name"))
	version, _ := root["version"].(map[string]any)
	versionNumber := strings.TrimSpace(stringField(version, "number"))
	if clusterName == "" || versionNumber == "" {
		return fmt.Errorf("target is not a confirmed Elasticsearch endpoint")
	}
	majorText, _, _ := strings.Cut(versionNumber, ".")
	major, err := strconv.Atoi(majorText)
	if err != nil || major < 1 || major > 99 {
		return fmt.Errorf("target returned an invalid Elasticsearch version")
	}
	if distribution := strings.TrimSpace(stringField(version, "distribution")); distribution != "" && !strings.EqualFold(distribution, "elasticsearch") {
		return fmt.Errorf("target reports a non-Elasticsearch distribution")
	}
	if tagline := strings.TrimSpace(stringField(root, "tagline")); tagline != "" && tagline != "You Know, for Search" {
		return fmt.Errorf("target returned an unexpected Elasticsearch identity")
	}
	return nil
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		if findings[i].Target != findings[j].Target {
			return findings[i].Target < findings[j].Target
		}
		if findings[i].Index != findings[j].Index {
			return findings[i].Index < findings[j].Index
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		if findings[i].FieldPath != findings[j].FieldPath {
			return findings[i].FieldPath < findings[j].FieldPath
		}
		if findings[i].DocumentID != findings[j].DocumentID {
			return findings[i].DocumentID < findings[j].DocumentID
		}
		if findings[i].Detector != findings[j].Detector {
			return findings[i].Detector < findings[j].Detector
		}
		if findings[i].CredentialType != findings[j].CredentialType {
			return findings[i].CredentialType < findings[j].CredentialType
		}
		if findings[i].ObjectPath != findings[j].ObjectPath {
			return findings[i].ObjectPath < findings[j].ObjectPath
		}
		return findings[i].MaskedPreview < findings[j].MaskedPreview
	})
}

func finalizeFindings(findings []Finding) {
	for index := range findings {
		finding := &findings[index]
		finding.ID = fmt.Sprintf("SEC-%06d", index+1)
		finding.Title = findingTitle(*finding)
		finding.Remediation = findingRemediation(*finding)
		finding.dedupFingerprint = ""
	}
}

func findingTitle(finding Finding) string {
	if finding.CredentialType != "" {
		return "Correlated credential material detected"
	}
	switch finding.Category {
	case "exposure.security_index":
		return "Elasticsearch security index is readable"
	case "credential.password_hash":
		return "Password hash material detected"
	case "credential.private_key":
		return "Private key material detected"
	case "material.public":
		return "Public cryptographic material detected"
	default:
		return "Sensitive credential material detected"
	}
}

func findingRemediation(finding Finding) string {
	switch finding.Category {
	case "exposure.security_index":
		return "Restrict access to Elasticsearch security indices and review the supplied identity's roles."
	case "material.public":
		return "Confirm that the public material is expected and stored in an appropriate field."
	case "credential.password_hash":
		return "Restrict access to password hashes and review whether this index is an approved identity store."
	default:
		return "Revoke or rotate the exposed credential, remove it from indexed documents, and restrict access to the affected index."
	}
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
		if report.FindingsTruncated {
			summary.FindingsTruncated = true
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
		summary.Occurrences += finding.Occurrences
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
