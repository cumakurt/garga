package fingerprint

import (
	"mime"
	"net/http"
	"strings"

	"github.com/cumakurt/garga/internal/probe"
)

const productElasticsearch = "Elasticsearch"

// Classification is the documented confidence band for a fingerprint score.
type Classification string

const (
	ClassificationUnknown   Classification = "unknown"
	ClassificationPossible  Classification = "possible"
	ClassificationLikely    Classification = "likely"
	ClassificationConfirmed Classification = "confirmed"
)

// Stable signal identifiers make score explanations testable and reportable.
const (
	SignalOpenSearchMarker = "opensearch_marker"
	SignalProductHeader    = "elastic_product_header"
	SignalTagline          = "elastic_tagline"
	SignalVersion          = "elastic_version"
	SignalBuildMetadata    = "elastic_build_metadata"
	SignalClusterIdentity  = "elastic_cluster_identity"
	SignalAuthChallenge    = "elastic_auth_challenge"
	SignalWarningHeader    = "elastic_warning_header"
	SignalJSONContent      = "json_content_type"
)

// Signal explains one fixed-weight positive or negative observation.
type Signal struct {
	Name   string
	Weight int
	Match  bool
	Detail string
}

// Result is a deterministic product decision and its complete score explanation.
type Result struct {
	Product        string
	Version        string
	Score          int
	Classification Classification
	Detected       bool
	Threshold      int
	Signals        []Signal
}

// Engine evaluates product-neutral probe results without performing I/O.
type Engine struct {
	threshold int
}

// New creates a fingerprint engine with an immutable detection threshold.
func New(options Options) (*Engine, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	return &Engine{threshold: options.Threshold}, nil
}

// Analyze combines independent headers, root semantics, and authentication evidence.
func (engine *Engine) Analyze(response probe.Result) Result {
	if engine == nil {
		return Result{Classification: ClassificationUnknown, Threshold: 100}
	}
	threshold := engine.threshold
	root := parseRoot(response.Body)
	openSearch := root.isOpenSearch
	productHeader := headerHasExactValue(response.Headers, "X-Elastic-Product", productElasticsearch)
	tagline := root.tagline == "You Know, for Search"
	version := root.version != ""
	buildMetadata := root.buildMetadataFields >= 2
	clusterIdentity := root.hasName && root.hasClusterName && root.hasClusterUUID
	authChallenge := (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden) && hasElasticAuthChallenge(response.Headers)
	warningHeader := hasElasticWarning(response.Headers)
	jsonContent := hasJSONContentType(response.Headers)

	signals := []Signal{
		{Name: SignalOpenSearchMarker, Weight: -100, Match: openSearch, Detail: detail(openSearch, "response identifies OpenSearch")},
		{Name: SignalProductHeader, Weight: 60, Match: productHeader, Detail: detail(productHeader, "X-Elastic-Product identifies Elasticsearch")},
		{Name: SignalTagline, Weight: 25, Match: tagline, Detail: detail(tagline, "canonical Elasticsearch tagline")},
		{Name: SignalVersion, Weight: 15, Match: version, Detail: versionDetail(root.version)},
		{Name: SignalBuildMetadata, Weight: 10, Match: buildMetadata, Detail: detail(buildMetadata, "Elasticsearch-style build metadata")},
		{Name: SignalClusterIdentity, Weight: 10, Match: clusterIdentity, Detail: detail(clusterIdentity, "name, cluster_name, and cluster_uuid are present")},
		{Name: SignalAuthChallenge, Weight: 25, Match: authChallenge, Detail: detail(authChallenge, "Elasticsearch security authentication challenge")},
		{Name: SignalWarningHeader, Weight: 10, Match: warningHeader, Detail: detail(warningHeader, "Elasticsearch deprecation warning")},
		{Name: SignalJSONContent, Weight: 5, Match: jsonContent, Detail: detail(jsonContent, "JSON response content type")},
	}

	score := 0
	for _, signal := range signals {
		if signal.Match {
			score += signal.Weight
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	detected := score >= threshold
	result := Result{
		Score:          score,
		Classification: classify(score),
		Detected:       detected,
		Threshold:      threshold,
		Signals:        signals,
	}
	if detected {
		result.Product = productElasticsearch
		result.Version = root.version
	}
	return result
}

func classify(score int) Classification {
	switch {
	case score >= 90:
		return ClassificationConfirmed
	case score >= 70:
		return ClassificationLikely
	case score >= 40:
		return ClassificationPossible
	default:
		return ClassificationUnknown
	}
}

func detail(matched bool, value string) string {
	if !matched {
		return ""
	}
	return value
}

func versionDetail(version string) string {
	if version == "" {
		return ""
	}
	return "version=" + version
}

func hasJSONContentType(headers []probe.HeaderField) bool {
	for _, value := range headerValues(headers, "Content-Type") {
		mediaType, _, err := mime.ParseMediaType(value)
		if err != nil {
			continue
		}
		mediaType = strings.ToLower(mediaType)
		if mediaType == "application/json" || mediaType == "application/vnd.elasticsearch+json" {
			return true
		}
	}
	return false
}

func hasElasticAuthChallenge(headers []probe.HeaderField) bool {
	for _, value := range headerValues(headers, "Www-Authenticate") {
		lower := strings.ToLower(value)
		if strings.Contains(lower, "apikey") ||
			(strings.Contains(lower, "basic") && strings.Contains(lower, `realm="security"`)) {
			return true
		}
	}
	return false
}

func hasElasticWarning(headers []probe.HeaderField) bool {
	for _, value := range headerValues(headers, "Warning") {
		if strings.Contains(value, "Elasticsearch-") {
			return true
		}
	}
	return false
}

func headerHasExactValue(headers []probe.HeaderField, name, want string) bool {
	for _, value := range headerValues(headers, name) {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

func headerValues(headers []probe.HeaderField, name string) []string {
	for _, field := range headers {
		if strings.EqualFold(field.Name, name) {
			return field.Values
		}
	}
	return nil
}
