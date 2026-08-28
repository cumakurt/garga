package advisory

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/cumakurt/garga/internal/vulnerability"
	"go.yaml.in/yaml/v3"
)

type candidateDocument struct {
	SchemaVersion string                   `yaml:"schema_version"`
	ID            string                   `yaml:"id"`
	Title         string                   `yaml:"title"`
	Description   string                   `yaml:"description"`
	Severity      string                   `yaml:"severity"`
	CVSS          *float64                 `yaml:"cvss,omitempty"`
	CVE           []string                 `yaml:"cve"`
	Product       string                   `yaml:"product"`
	Affected      []string                 `yaml:"affected"`
	Detection     string                   `yaml:"detection"`
	References    []string                 `yaml:"references,omitempty"`
	Remediation   string                   `yaml:"remediation"`
	Threat        *candidateThreatDocument `yaml:"threat,omitempty"`
}

type candidateThreatDocument struct {
	KnownExploited bool     `yaml:"known_exploited"`
	EPSS           *float64 `yaml:"epss,omitempty"`
	EPSSPercentile *float64 `yaml:"epss_percentile,omitempty"`
	Updated        string   `yaml:"updated"`
}

func WriteCandidates(directory string, advisories []Advisory) ([]string, error) {
	directory = filepath.Clean(strings.TrimSpace(directory))
	if directory == "" || directory == "." || directory == string(filepath.Separator) {
		return nil, fmt.Errorf("write advisory candidates: output directory is required")
	}
	if _, err := os.Lstat(directory); err == nil {
		return nil, fmt.Errorf("write advisory candidates: output directory already exists")
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("write advisory candidates: inspect output directory: %w", err)
	}
	ready := make([]Advisory, 0)
	for _, item := range advisories {
		if item.CandidateStatus == "ready" {
			ready = append(ready, item)
		}
	}
	if len(ready) == 0 {
		return nil, nil
	}
	if len(ready) > vulnerability.MaxSignatureFiles {
		return nil, fmt.Errorf("write advisory candidates: candidate count exceeds %d", vulnerability.MaxSignatureFiles)
	}
	sort.Slice(ready, func(left, right int) bool { return ready[left].CVE < ready[right].CVE })
	staging, err := os.MkdirTemp(filepath.Dir(directory), ".garga-advisories-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("write advisory candidates: create staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	written := make([]string, 0, len(ready))
	for _, item := range ready {
		name := strings.ToLower(item.CVE) + ".yaml"
		contents, err := marshalCandidate(item)
		if err != nil {
			return nil, err
		}
		if _, err := vulnerability.Parse(name, contents); err != nil {
			return nil, fmt.Errorf("write advisory candidates: generated %s did not validate: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(staging, name), contents, 0o600); err != nil {
			return nil, fmt.Errorf("write advisory candidates: create %s: %w", name, err)
		}
		written = append(written, name)
	}
	if err := os.Rename(staging, directory); err != nil {
		return nil, fmt.Errorf("write advisory candidates: activate output directory: %w", err)
	}
	return written, nil
}

func marshalCandidate(item Advisory) ([]byte, error) {
	document := candidateDocument{
		SchemaVersion: vulnerability.SignatureSchemaVersion,
		ID:            "garga.vuln." + strings.ToLower(item.CVE),
		Title:         truncateUTF8(strings.TrimSpace(item.Title), 256),
		Description:   truncateUTF8(strings.TrimSpace(item.Description), 8192),
		Severity:      item.Severity,
		CVSS:          item.CVSS,
		CVE:           []string{item.CVE},
		Product:       "elasticsearch",
		Affected:      append([]string(nil), item.Affected...),
		Detection:     vulnerability.DetectionVersion,
		References:    append([]string(nil), item.References...),
		Remediation:   "Upgrade Elasticsearch to a version outside the affected ranges for this advisory.",
	}
	if len(document.References) > 16 {
		document.References = document.References[:16]
	}
	if item.KnownExploited || item.EPSS != nil || item.EPSSPercentile != nil {
		document.Threat = &candidateThreatDocument{
			KnownExploited: item.KnownExploited,
			EPSS:           item.EPSS,
			EPSSPercentile: item.EPSSPercentile,
			Updated:        item.ThreatUpdated,
		}
	}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("write advisory candidates: encode %s: %w", item.CVE, err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("write advisory candidates: close YAML encoder: %w", err)
	}
	return output.Bytes(), nil
}

func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return strings.TrimSpace(value)
}
