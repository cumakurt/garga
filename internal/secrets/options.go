package secrets

import (
	"fmt"
	"strings"
	"time"
)

const (
	DefaultTimeout        = 10 * time.Minute
	DefaultRequestTimeout = 15 * time.Second
	DefaultConcurrency    = 2
	DefaultRateLimit      = 5.0
	DefaultSampleSize     = 100
	DefaultMaxDocuments   = 10000
	DefaultMaxDepth       = 8
	DefaultMaxArrayItems  = 64
	DefaultMaxObjectSize  = 256
	DefaultMaxFieldBytes  = 1 << 20
	DefaultSearchBatch    = 25
	DefaultRetries        = 3
	maxConcurrency        = 32
	maxRateLimit          = 100.0
	maxSampleSize         = 1000
	maxDocuments          = 100000
	maxDepth              = 32
	maxArrayItems         = 1000
	maxObjectSize         = 10000
	maxFieldBytes         = 8 << 20
	maxSearchBatch        = 100
	maxRetries            = 8
	maxIndexFilters       = 256
)

// Options configures an authorized, read-only sensitive-data scan.
type Options struct {
	User                 string
	PasswordEnv          string
	APIKeyEnv            string
	BearerTokenEnv       string
	CACert               string
	ClientCert           string
	ClientKey            string
	Insecure             bool
	AllowPlaintextAuth   bool
	Timeout              time.Duration
	RequestTimeout       time.Duration
	Concurrency          int
	RateLimit            float64
	SampleSize           int
	MaxDocuments         int
	Indices              []string
	ExcludeIndices       []string
	IncludeSystemIndices bool
	MinConfidence        Confidence
	Verbose              bool
	MaxDepth             int
	MaxArrayItems        int
	MaxObjectSize        int
	MaxFieldBytes        int
	SearchBatch          int
	Retries              int
	DeepScan             bool
	ScanGenericFields    bool
	EntropyEnabled       bool
	BroadCorrelation     bool
	MaxSourceFields      int
}

func defaultOptions() Options {
	return Options{
		Timeout:         DefaultTimeout,
		RequestTimeout:  DefaultRequestTimeout,
		Concurrency:     DefaultConcurrency,
		RateLimit:       DefaultRateLimit,
		SampleSize:      DefaultSampleSize,
		MaxDocuments:    DefaultMaxDocuments,
		MinConfidence:   ConfidenceMedium,
		MaxDepth:        DefaultMaxDepth,
		MaxArrayItems:   DefaultMaxArrayItems,
		MaxObjectSize:   DefaultMaxObjectSize,
		MaxFieldBytes:   DefaultMaxFieldBytes,
		SearchBatch:     DefaultSearchBatch,
		Retries:         DefaultRetries,
		EntropyEnabled:  true,
		MaxSourceFields: DefaultMaxSourceFields,
	}
}

func (options Options) withDefaults() Options {
	defaults := defaultOptions()
	if options.Timeout <= 0 {
		options.Timeout = defaults.Timeout
	}
	if options.RequestTimeout <= 0 {
		options.RequestTimeout = defaults.RequestTimeout
	}
	if options.Concurrency <= 0 {
		options.Concurrency = defaults.Concurrency
	}
	if options.RateLimit <= 0 {
		options.RateLimit = defaults.RateLimit
	}
	if options.SampleSize <= 0 {
		options.SampleSize = defaults.SampleSize
	}
	if options.MaxDocuments <= 0 {
		options.MaxDocuments = defaults.MaxDocuments
	}
	if options.MinConfidence == "" {
		options.MinConfidence = defaults.MinConfidence
	}
	if options.MaxDepth <= 0 {
		options.MaxDepth = defaults.MaxDepth
	}
	if options.MaxArrayItems <= 0 {
		options.MaxArrayItems = defaults.MaxArrayItems
	}
	if options.MaxObjectSize <= 0 {
		options.MaxObjectSize = defaults.MaxObjectSize
	}
	if options.MaxFieldBytes <= 0 {
		options.MaxFieldBytes = defaults.MaxFieldBytes
	}
	if options.SearchBatch <= 0 {
		options.SearchBatch = defaults.SearchBatch
	}
	if options.MaxSourceFields <= 0 {
		options.MaxSourceFields = defaults.MaxSourceFields
	}
	if options.Retries < 0 {
		options.Retries = defaults.Retries
	}
	return options
}

func (options Options) validate() error {
	options = options.withDefaults()
	if options.Timeout > 24*time.Hour {
		return fmt.Errorf("secrets timeout must be at most 24h")
	}
	if options.RequestTimeout > 5*time.Minute {
		return fmt.Errorf("secrets request timeout must be at most 5m")
	}
	if options.Concurrency > maxConcurrency {
		return fmt.Errorf("secrets concurrency must be at most %d", maxConcurrency)
	}
	if options.RateLimit > maxRateLimit {
		return fmt.Errorf("secrets rate limit must be at most %g requests/second", maxRateLimit)
	}
	if options.SampleSize > maxSampleSize {
		return fmt.Errorf("secrets sample size must be at most %d", maxSampleSize)
	}
	if options.MaxDocuments > maxDocuments {
		return fmt.Errorf("secrets max documents must be at most %d", maxDocuments)
	}
	if confidenceRank(options.MinConfidence) == 0 {
		return fmt.Errorf("secrets min-confidence must be low, medium, high, or confirmed-pattern")
	}
	if options.MaxDepth > maxDepth {
		return fmt.Errorf("secrets max-depth must be at most %d", maxDepth)
	}
	if options.MaxArrayItems > maxArrayItems {
		return fmt.Errorf("secrets max-array-items must be at most %d", maxArrayItems)
	}
	if options.MaxObjectSize > maxObjectSize {
		return fmt.Errorf("secrets max-object-size must be at most %d", maxObjectSize)
	}
	if options.MaxFieldBytes > maxFieldBytes {
		return fmt.Errorf("secrets max-field-bytes must be at most %d", maxFieldBytes)
	}
	if options.SearchBatch > maxSearchBatch {
		return fmt.Errorf("secrets search batch must be at most %d", maxSearchBatch)
	}
	if options.MaxSourceFields > maxSourceFieldsCap {
		return fmt.Errorf("secrets max source fields must be at most %d", maxSourceFieldsCap)
	}
	if options.Retries > maxRetries {
		return fmt.Errorf("secrets retries must be at most %d", maxRetries)
	}
	if len(options.Indices) > maxIndexFilters || len(options.ExcludeIndices) > maxIndexFilters {
		return fmt.Errorf("secrets index filters must be at most %d entries", maxIndexFilters)
	}
	mechanisms := 0
	if strings.TrimSpace(options.PasswordEnv) != "" {
		mechanisms++
	}
	if strings.TrimSpace(options.APIKeyEnv) != "" {
		mechanisms++
	}
	if strings.TrimSpace(options.BearerTokenEnv) != "" {
		mechanisms++
	}
	if mechanisms > 1 {
		return fmt.Errorf("select only one secrets authentication mechanism")
	}
	if strings.TrimSpace(options.PasswordEnv) != "" && strings.TrimSpace(options.User) == "" {
		return fmt.Errorf("--password-env requires --user")
	}
	certParts := 0
	if strings.TrimSpace(options.ClientCert) != "" {
		certParts++
	}
	if strings.TrimSpace(options.ClientKey) != "" {
		certParts++
	}
	if certParts == 1 {
		return fmt.Errorf("--client-cert and --client-key must be supplied together")
	}
	return nil
}

func ParseConfidence(value string) (Confidence, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return ConfidenceLow, nil
	case "medium":
		return ConfidenceMedium, nil
	case "high":
		return ConfidenceHigh, nil
	case "confirmed", "confirmed-pattern":
		return ConfidenceConfirmed, nil
	default:
		return "", fmt.Errorf("min-confidence must be low, medium, high, or confirmed-pattern")
	}
}

func ParseFormat(value string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "json":
		return FormatJSON, nil
	case "jsonl":
		return FormatJSONL, nil
	case "table":
		return FormatTable, nil
	case "sarif":
		return FormatSARIF, nil
	default:
		return "", fmt.Errorf("format must be json, jsonl, table, or sarif")
	}
}
