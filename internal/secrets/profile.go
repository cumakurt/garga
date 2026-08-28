package secrets

import "time"

// ScanMode is the operator-selected secrets analysis profile.
type ScanMode string

const (
	ScanModeNormal ScanMode = "normal"
	ScanModeDeep   ScanMode = "deep"
)

const (
	DefaultMaxSourceFields     = 32
	DefaultDeepSampleSize      = 500
	DefaultDeepMaxDocuments    = 50000
	DefaultDeepMaxFieldBytes   = 4 << 20
	DefaultDeepMaxDepth        = 16
	DefaultDeepMaxArrayItems   = 256
	DefaultDeepMaxObjectSize   = 1024
	DefaultDeepMaxSourceFields = 128
	DefaultDeepSearchBatch     = 50
	maxSourceFieldsCap         = 256
)

// ScanProfile is the central normal/deep behavior configuration.
// Callers should not scatter DeepScan conditionals; apply a profile once.
type ScanProfile struct {
	Mode              ScanMode
	SampleSize        int
	MaxDocuments      int
	MaxFieldBytes     int
	MaxDepth          int
	MaxArrayItems     int
	MaxObjectSize     int
	MaxSourceFields   int
	SearchBatch       int
	ScanGenericFields bool
	EntropyEnabled    bool
	BroadCorrelation  bool
}

// NormalProfile is the production-safe default.
func NormalProfile() ScanProfile {
	return ScanProfile{
		Mode:              ScanModeNormal,
		SampleSize:        DefaultSampleSize,
		MaxDocuments:      DefaultMaxDocuments,
		MaxFieldBytes:     DefaultMaxFieldBytes,
		MaxDepth:          DefaultMaxDepth,
		MaxArrayItems:     DefaultMaxArrayItems,
		MaxObjectSize:     DefaultMaxObjectSize,
		MaxSourceFields:   DefaultMaxSourceFields,
		SearchBatch:       DefaultSearchBatch,
		ScanGenericFields: false,
		EntropyEnabled:    true,
		BroadCorrelation:  false,
	}
}

// DeepScanProfile raises coverage while remaining bounded.
func DeepScanProfile() ScanProfile {
	return ScanProfile{
		Mode:              ScanModeDeep,
		SampleSize:        DefaultDeepSampleSize,
		MaxDocuments:      DefaultDeepMaxDocuments,
		MaxFieldBytes:     DefaultDeepMaxFieldBytes,
		MaxDepth:          DefaultDeepMaxDepth,
		MaxArrayItems:     DefaultDeepMaxArrayItems,
		MaxObjectSize:     DefaultDeepMaxObjectSize,
		MaxSourceFields:   DefaultDeepMaxSourceFields,
		SearchBatch:       DefaultDeepSearchBatch,
		ScanGenericFields: true,
		EntropyEnabled:    true,
		BroadCorrelation:  true,
	}
}

// ProfileOverrides records which operator flags should replace profile defaults.
type ProfileOverrides struct {
	SampleSize      bool
	MaxDocuments    bool
	MaxFieldBytes   bool
	MaxDepth        bool
	MaxArrayItems   bool
	MaxObjectSize   bool
	MaxSourceFields bool
	SearchBatch     bool
}

// ApplyProfile copies profile limits onto options unless the operator overrode them.
func ApplyProfile(options *Options, profile ScanProfile, overrides ProfileOverrides) {
	if options == nil {
		return
	}
	options.DeepScan = profile.Mode == ScanModeDeep
	options.ScanGenericFields = profile.ScanGenericFields
	options.EntropyEnabled = profile.EntropyEnabled
	options.BroadCorrelation = profile.BroadCorrelation
	if !overrides.SampleSize {
		options.SampleSize = profile.SampleSize
	}
	if !overrides.MaxDocuments {
		options.MaxDocuments = profile.MaxDocuments
	}
	if !overrides.MaxFieldBytes {
		options.MaxFieldBytes = profile.MaxFieldBytes
	}
	if !overrides.MaxDepth {
		options.MaxDepth = profile.MaxDepth
	}
	if !overrides.MaxArrayItems {
		options.MaxArrayItems = profile.MaxArrayItems
	}
	if !overrides.MaxObjectSize {
		options.MaxObjectSize = profile.MaxObjectSize
	}
	if !overrides.MaxSourceFields {
		options.MaxSourceFields = profile.MaxSourceFields
	}
	if !overrides.SearchBatch {
		options.SearchBatch = profile.SearchBatch
	}
}

func (options Options) scanMode() ScanMode {
	if options.DeepScan {
		return ScanModeDeep
	}
	return ScanModeNormal
}

func (options Options) walkLimits() walkLimits {
	return walkLimits{
		maxDepth:          options.MaxDepth,
		maxArrayItems:     options.MaxArrayItems,
		maxObjectSize:     options.MaxObjectSize,
		maxFieldBytes:     options.MaxFieldBytes,
		scanGenericFields: options.ScanGenericFields,
		entropyEnabled:    options.EntropyEnabled,
		broadCorrelation:  options.BroadCorrelation,
		maxHits:           MaxReportFindings,
	}
}

func scanDurationMS(started, finished time.Time) int64 {
	if started.IsZero() || finished.IsZero() || finished.Before(started) {
		return 0
	}
	return finished.Sub(started).Milliseconds()
}
