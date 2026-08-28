package advisory

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cumakurt/garga/internal/vulnerability"
	"go.yaml.in/yaml/v3"
)

type CorpusResult struct {
	Updated []string `json:"updated,omitempty"`
	Added   []string `json:"added,omitempty"`
}

func BuildCorpus(source, output string, advisories []Advisory, includeCandidates bool) (CorpusResult, error) {
	if _, err := vulnerability.LoadDir(source); err != nil {
		return CorpusResult{}, fmt.Errorf("build advisory corpus: validate source: %w", err)
	}
	output = filepath.Clean(strings.TrimSpace(output))
	if output == "" || output == "." || output == string(filepath.Separator) {
		return CorpusResult{}, fmt.Errorf("build advisory corpus: output directory is required")
	}
	if _, err := os.Lstat(output); err == nil {
		return CorpusResult{}, fmt.Errorf("build advisory corpus: output directory already exists")
	} else if !os.IsNotExist(err) {
		return CorpusResult{}, fmt.Errorf("build advisory corpus: inspect output directory: %w", err)
	}

	byCVE := make(map[string]Advisory, len(advisories))
	for _, item := range advisories {
		byCVE[item.CVE] = item
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return CorpusResult{}, fmt.Errorf("build advisory corpus: read source: %w", err)
	}
	staging, err := os.MkdirTemp(filepath.Dir(output), ".garga-corpus-*.tmp")
	if err != nil {
		return CorpusResult{}, fmt.Errorf("build advisory corpus: create staging directory: %w", err)
	}
	defer os.RemoveAll(staging)

	result := CorpusResult{}
	fileCount := 0
	for _, entry := range entries {
		name := entry.Name()
		extension := strings.ToLower(filepath.Ext(name))
		if strings.HasPrefix(name, ".") || (extension != ".yaml" && extension != ".yml") {
			continue
		}
		fileCount++
		contents, err := readSignatureFile(source, name)
		if err != nil {
			return CorpusResult{}, fmt.Errorf("build advisory corpus: read %q: %w", name, err)
		}
		signature, err := vulnerability.Parse(name, contents)
		if err != nil {
			return CorpusResult{}, fmt.Errorf("build advisory corpus: %w", err)
		}
		enriched, changed, err := enrichSignature(contents, signature.CVE, byCVE)
		if err != nil {
			return CorpusResult{}, fmt.Errorf("build advisory corpus: enrich %q: %w", name, err)
		}
		if _, err := vulnerability.Parse(name, enriched); err != nil {
			return CorpusResult{}, fmt.Errorf("build advisory corpus: enriched %q did not validate: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(staging, name), enriched, 0o600); err != nil {
			return CorpusResult{}, fmt.Errorf("build advisory corpus: write %q: %w", name, err)
		}
		if changed {
			result.Updated = append(result.Updated, name)
		}
	}
	if includeCandidates {
		for _, item := range advisories {
			if item.CandidateStatus != "ready" {
				continue
			}
			name := strings.ToLower(item.CVE) + ".yaml"
			contents, err := marshalCandidate(item)
			if err != nil {
				return CorpusResult{}, err
			}
			if _, err := vulnerability.Parse(name, contents); err != nil {
				return CorpusResult{}, fmt.Errorf("build advisory corpus: generated %q did not validate: %w", name, err)
			}
			if err := os.WriteFile(filepath.Join(staging, name), contents, 0o600); err != nil {
				return CorpusResult{}, fmt.Errorf("build advisory corpus: write %q: %w", name, err)
			}
			fileCount++
			result.Added = append(result.Added, name)
		}
	}
	if fileCount > vulnerability.MaxSignatureFiles {
		return CorpusResult{}, fmt.Errorf("build advisory corpus: result exceeds %d signatures", vulnerability.MaxSignatureFiles)
	}
	if _, err := vulnerability.LoadDir(staging); err != nil {
		return CorpusResult{}, fmt.Errorf("build advisory corpus: validate result: %w", err)
	}
	sort.Strings(result.Updated)
	sort.Strings(result.Added)
	if err := os.Rename(staging, output); err != nil {
		return CorpusResult{}, fmt.Errorf("build advisory corpus: activate output: %w", err)
	}
	return result, nil
}

func readSignatureFile(directory, name string) ([]byte, error) {
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("signature %q must be a regular non-symlink file", name)
	}
	if info.Size() < 1 || info.Size() > vulnerability.MaxSignatureBytes {
		return nil, fmt.Errorf("signature %q size is invalid", name)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open signature %q: %w", name, err)
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
		_ = file.Close()
		return nil, fmt.Errorf("signature %q changed while opening", name)
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, vulnerability.MaxSignatureBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, fmt.Errorf("read signature %q", name)
	}
	if int64(len(contents)) != openedInfo.Size() {
		return nil, fmt.Errorf("signature %q changed while reading", name)
	}
	return contents, nil
}

func enrichSignature(contents []byte, cves []string, advisories map[string]Advisory) ([]byte, bool, error) {
	selected, found := selectThreat(cves, advisories)
	if !found || (selected.EPSS == nil && selected.EPSSPercentile == nil && !selected.KnownExploited) {
		return contents, false, nil
	}
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, false, err
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("signature must contain one YAML document")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, false, fmt.Errorf("signature root must be a mapping")
	}
	root := document.Content[0]
	threatIndex := -1
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value == "threat" {
			threatIndex = index
			break
		}
	}
	if threatIndex < 0 {
		enriched := appendThreatBlock(contents, selected)
		return enriched, !bytes.Equal(contents, enriched), nil
	}
	startLine := root.Content[threatIndex].Line
	endLine := 0
	if threatIndex+2 < len(root.Content) {
		endLine = root.Content[threatIndex+2].Line
	}
	enriched, err := replaceYAMLLines(contents, startLine, endLine, threatBlock(selected))
	if err != nil {
		return nil, false, err
	}
	return enriched, !bytes.Equal(contents, enriched), nil
}

func appendThreatBlock(contents []byte, item Advisory) []byte {
	var block strings.Builder
	if len(contents) > 0 && contents[len(contents)-1] != '\n' {
		block.WriteByte('\n')
	}
	block.WriteString(threatBlock(item))
	return append(append([]byte(nil), contents...), block.String()...)
}

func threatBlock(item Advisory) string {
	var block strings.Builder
	block.WriteString("threat:\n")
	block.WriteString("  known_exploited: ")
	block.WriteString(strconv.FormatBool(item.KnownExploited))
	block.WriteByte('\n')
	if item.EPSS != nil {
		block.WriteString("  epss: ")
		block.WriteString(strconv.FormatFloat(*item.EPSS, 'f', -1, 64))
		block.WriteByte('\n')
	}
	if item.EPSSPercentile != nil {
		block.WriteString("  epss_percentile: ")
		block.WriteString(strconv.FormatFloat(*item.EPSSPercentile, 'f', -1, 64))
		block.WriteByte('\n')
	}
	block.WriteString("  updated: \"")
	block.WriteString(item.ThreatUpdated)
	block.WriteString("\"\n")
	return block.String()
}

func replaceYAMLLines(contents []byte, startLine, endLine int, replacement string) ([]byte, error) {
	if startLine < 1 {
		return nil, fmt.Errorf("threat YAML position is invalid")
	}
	lines := bytes.SplitAfter(contents, []byte("\n"))
	startIndex := startLine - 1
	endIndex := len(lines)
	if endLine > 0 {
		endIndex = endLine - 1
	}
	if startIndex >= len(lines) || endIndex < startIndex || endIndex > len(lines) {
		return nil, fmt.Errorf("threat YAML range is invalid")
	}
	result := make([]byte, 0, len(contents)+len(replacement))
	for _, line := range lines[:startIndex] {
		result = append(result, line...)
	}
	result = append(result, replacement...)
	for _, line := range lines[endIndex:] {
		result = append(result, line...)
	}
	return result, nil
}

func selectThreat(cves []string, advisories map[string]Advisory) (Advisory, bool) {
	var selected Advisory
	found := false
	for _, cve := range cves {
		item, exists := advisories[cve]
		if !exists {
			continue
		}
		if !found {
			selected = item
			found = true
			continue
		}
		selected.KnownExploited = selected.KnownExploited || item.KnownExploited
		if item.EPSS != nil && (selected.EPSS == nil || *item.EPSS > *selected.EPSS) {
			selected.EPSS = item.EPSS
		}
		if item.EPSSPercentile != nil && (selected.EPSSPercentile == nil || *item.EPSSPercentile > *selected.EPSSPercentile) {
			selected.EPSSPercentile = item.EPSSPercentile
		}
		if item.ThreatUpdated > selected.ThreatUpdated {
			selected.ThreatUpdated = item.ThreatUpdated
		}
	}
	return selected, found
}
