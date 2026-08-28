package advisory

const SchemaVersion = "0.1"

type Advisory struct {
	CVE               string   `json:"cve"`
	ESA               string   `json:"esa,omitempty"`
	Title             string   `json:"title"`
	Description       string   `json:"description,omitempty"`
	Published         string   `json:"published,omitempty"`
	Updated           string   `json:"updated,omitempty"`
	URL               string   `json:"url"`
	CVSS              *float64 `json:"cvss,omitempty"`
	Severity          string   `json:"severity,omitempty"`
	Affected          []string `json:"affected,omitempty"`
	References        []string `json:"references,omitempty"`
	KnownExploited    bool     `json:"known_exploited"`
	EPSS              *float64 `json:"epss,omitempty"`
	EPSSPercentile    *float64 `json:"epss_percentile,omitempty"`
	ThreatUpdated     string   `json:"threat_updated,omitempty"`
	SignaturePresent  bool     `json:"signature_present"`
	CandidateStatus   string   `json:"candidate_status"`
	CandidateReason   string   `json:"candidate_reason,omitempty"`
	SignatureFilename string   `json:"signature_filename,omitempty"`
}

type Sources struct {
	Elastic string `json:"elastic"`
	CVE     string `json:"cve"`
	CISAKEV string `json:"cisa_kev"`
	EPSS    string `json:"epss"`
}

type Summary struct {
	Advisories int `json:"advisories"`
	Present    int `json:"present"`
	Ready      int `json:"ready"`
	Blocked    int `json:"blocked"`
}

type Snapshot struct {
	SchemaVersion string     `json:"schema_version"`
	AsOf          string     `json:"as_of,omitempty"`
	Sources       Sources    `json:"sources"`
	Summary       Summary    `json:"summary"`
	Advisories    []Advisory `json:"advisories"`
}

type Result struct {
	Snapshot          Snapshot `json:"snapshot"`
	WrittenCandidates []string `json:"written_candidates,omitempty"`
}
