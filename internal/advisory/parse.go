package advisory

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/vulnerability"
)

const maxEPSSDecompressedBytes = 128 << 20

type elasticCategoryDocument struct {
	TopicList struct {
		MoreTopicsURL string `json:"more_topics_url"`
		Topics        []struct {
			ID        int    `json:"id"`
			Title     string `json:"title"`
			Slug      string `json:"slug"`
			CreatedAt string `json:"created_at"`
		} `json:"topics"`
	} `json:"topic_list"`
}

type elasticTopicDocument struct {
	PostStream struct {
		Posts []struct {
			Cooked string `json:"cooked"`
		} `json:"posts"`
	} `json:"post_stream"`
}

type cveRecord struct {
	CVE             string
	Title           string
	Description     string
	Published       string
	Updated         string
	CVSS            *float64
	Severity        string
	Affected        []string
	References      []string
	CandidateReason string
}

type cveRecordDocument struct {
	Metadata struct {
		CVE       string `json:"cveId"`
		Published string `json:"datePublished"`
		Updated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Title        string `json:"title"`
			Descriptions []struct {
				Language string `json:"lang"`
				Value    string `json:"value"`
			} `json:"descriptions"`
			Affected []struct {
				Product       string `json:"product"`
				DefaultStatus string `json:"defaultStatus"`
				Versions      []struct {
					Version         string `json:"version"`
					Status          string `json:"status"`
					LessThan        string `json:"lessThan"`
					LessThanOrEqual string `json:"lessThanOrEqual"`
					VersionType     string `json:"versionType"`
					Changes         []any  `json:"changes"`
				} `json:"versions"`
			} `json:"affected"`
			Metrics []struct {
				CVSSV40 *cvssMetric `json:"cvssV4_0"`
				CVSSV31 *cvssMetric `json:"cvssV3_1"`
				CVSSV30 *cvssMetric `json:"cvssV3_0"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cna"`
	} `json:"containers"`
}

type cvssMetric struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

func fetchCVERecord(ctx context.Context, fetcher Fetcher, baseURL, cve string) (cveRecord, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" {
		return cveRecord{}, fmt.Errorf("sync advisories: CVE API URL is invalid")
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/" + url.PathEscape(cve)
	contents, err := fetcher.Get(ctx, parsed.String(), maxCVERecordBytes)
	if err != nil {
		return cveRecord{}, fmt.Errorf("sync advisories: fetch CVE record %s: %w", cve, err)
	}
	var document cveRecordDocument
	if err := json.Unmarshal(contents, &document); err != nil || document.Metadata.CVE != cve {
		return cveRecord{}, fmt.Errorf("sync advisories: CVE record %s is invalid", cve)
	}
	return parseCVERecord(document), nil
}

func parseCVERecord(document cveRecordDocument) cveRecord {
	record := cveRecord{
		CVE:       document.Metadata.CVE,
		Title:     strings.TrimSpace(document.Containers.CNA.Title),
		Published: parseTimestamp(document.Metadata.Published),
		Updated:   parseTimestamp(document.Metadata.Updated),
	}
	for _, description := range document.Containers.CNA.Descriptions {
		if strings.EqualFold(description.Language, "en") {
			record.Description = strings.TrimSpace(description.Value)
			break
		}
	}
	for _, metricGroup := range document.Containers.CNA.Metrics {
		for _, metric := range []*cvssMetric{metricGroup.CVSSV40, metricGroup.CVSSV31, metricGroup.CVSSV30} {
			if metric == nil || metric.BaseScore < 0 || metric.BaseScore > 10 {
				continue
			}
			record.CVSS = floatPointer(metric.BaseScore)
			record.Severity = normalizeSeverity(metric.BaseSeverity, metric.BaseScore)
			break
		}
		if record.CVSS != nil {
			break
		}
	}
	record.Affected, record.CandidateReason = affectedRanges(document)
	for _, reference := range document.Containers.CNA.References {
		if validReference(reference.URL) {
			record.References = append(record.References, strings.TrimSpace(reference.URL))
		}
	}
	record.References = uniqueSorted(record.References)
	return record
}

func affectedRanges(document cveRecordDocument) ([]string, string) {
	ranges := make([]string, 0)
	foundProduct := false
	for _, product := range document.Containers.CNA.Affected {
		if !strings.EqualFold(strings.TrimSpace(product.Product), "Elasticsearch") {
			continue
		}
		foundProduct = true
		if !strings.EqualFold(strings.TrimSpace(product.DefaultStatus), "unaffected") {
			return nil, "Elasticsearch CVE record does not use an unaffected default status"
		}
		for _, version := range product.Versions {
			if !strings.EqualFold(strings.TrimSpace(version.Status), "affected") || len(version.Changes) != 0 {
				return nil, "Elasticsearch CVE version data contains unsupported status changes"
			}
			versionType := strings.ToLower(strings.TrimSpace(version.VersionType))
			if versionType != "" && versionType != "semver" {
				return nil, "Elasticsearch CVE version data is not semantic-version based"
			}
			start := strings.TrimSpace(version.Version)
			startVersion, err := vulnerability.ParseVersion(start)
			if err != nil {
				return nil, "Elasticsearch CVE affected version start is not safely convertible"
			}
			expression := ">=" + start
			switch {
			case strings.TrimSpace(version.LessThan) != "":
				end := strings.TrimSpace(version.LessThan)
				endVersion, err := vulnerability.ParseVersion(end)
				if err != nil || endVersion.Compare(startVersion) <= 0 {
					return nil, "Elasticsearch CVE affected version end is not safely convertible"
				}
				expression += " <" + end
			case strings.TrimSpace(version.LessThanOrEqual) != "":
				end := strings.TrimSpace(version.LessThanOrEqual)
				endVersion, err := vulnerability.ParseVersion(end)
				if err != nil || endVersion.Compare(startVersion) < 0 {
					return nil, "Elasticsearch CVE affected version end is not safely convertible"
				}
				expression += " <=" + end
			default:
				expression = "=" + start
			}
			if _, err := vulnerability.ParseRange(expression); err != nil {
				return nil, "Elasticsearch CVE affected range is not safely convertible"
			}
			ranges = append(ranges, expression)
		}
	}
	if !foundProduct {
		return nil, "CVE record has no Elasticsearch affected-product entry"
	}
	ranges = uniqueSorted(ranges)
	if len(ranges) == 0 || len(ranges) > 16 {
		return nil, "CVE record has no supported Elasticsearch affected ranges"
	}
	return ranges, ""
}

func normalizeSeverity(value string, score float64) string {
	severity := strings.ToLower(strings.TrimSpace(value))
	switch severity {
	case "critical", "high", "medium", "low":
		return severity
	}
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

func validReference(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	return err == nil && (parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host != "" && parsed.User == nil
}

func advisoryFromRecord(topic elasticTopic, record cveRecord) Advisory {
	references := append([]string(nil), record.References...)
	references = append(references, topic.URL, "https://nvd.nist.gov/vuln/detail/"+record.CVE)
	return Advisory{
		CVE: record.CVE, ESA: topic.ESA, Title: record.Title, Description: record.Description,
		Published: record.Published, Updated: record.Updated, URL: topic.URL, CVSS: record.CVSS,
		Severity: record.Severity, Affected: record.Affected, References: uniqueSorted(references),
		CandidateReason: record.CandidateReason,
	}
}

func fetchKEV(ctx context.Context, fetcher Fetcher, address string) (map[string]bool, error) {
	contents, err := fetcher.Get(ctx, address, maxKEVBytes)
	if err != nil {
		return nil, fmt.Errorf("sync advisories: fetch CISA KEV: %w", err)
	}
	var document struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(contents, &document); err != nil || len(document.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("sync advisories: CISA KEV response is invalid")
	}
	result := make(map[string]bool, len(document.Vulnerabilities))
	for _, item := range document.Vulnerabilities {
		cve := strings.TrimSpace(item.CVE)
		if cveExactPattern.MatchString(cve) {
			result[cve] = true
		}
	}
	return result, nil
}

type epssScore struct {
	Score      float64
	Percentile float64
}

func fetchEPSS(ctx context.Context, fetcher Fetcher, address string, desired map[string]struct{}) (map[string]epssScore, string, error) {
	contents, err := fetcher.Get(ctx, address, maxEPSSBytes)
	if err != nil {
		return nil, "", fmt.Errorf("sync advisories: fetch FIRST EPSS: %w", err)
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(contents))
	if err != nil {
		return nil, "", fmt.Errorf("sync advisories: FIRST EPSS response is not gzip data")
	}
	defer gzipReader.Close()
	limited := &io.LimitedReader{R: gzipReader, N: maxEPSSDecompressedBytes + 1}
	buffered := bufio.NewReader(limited)
	firstLine, err := buffered.ReadString('\n')
	if err != nil {
		return nil, "", fmt.Errorf("sync advisories: FIRST EPSS header is invalid")
	}
	asOf := parseEPSSDate(firstLine)
	reader := csv.NewReader(buffered)
	reader.FieldsPerRecord = 3
	header, err := reader.Read()
	if err != nil || len(header) != 3 || strings.TrimSpace(header[0]) != "cve" {
		return nil, "", fmt.Errorf("sync advisories: FIRST EPSS CSV header is invalid")
	}
	result := make(map[string]epssScore, len(desired))
	for {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		record, readErr := reader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, "", fmt.Errorf("sync advisories: FIRST EPSS CSV is invalid")
		}
		cve := strings.TrimSpace(record[0])
		if _, wanted := desired[cve]; !wanted {
			continue
		}
		score, scoreErr := strconv.ParseFloat(strings.TrimSpace(record[1]), 64)
		percentile, percentileErr := strconv.ParseFloat(strings.TrimSpace(record[2]), 64)
		if scoreErr != nil || percentileErr != nil || !finiteUnit(score) || !finiteUnit(percentile) {
			return nil, "", fmt.Errorf("sync advisories: FIRST EPSS score is invalid")
		}
		result[cve] = epssScore{Score: score, Percentile: percentile}
	}
	if limited.N <= 0 {
		return nil, "", fmt.Errorf("sync advisories: FIRST EPSS data exceeds %d bytes", maxEPSSDecompressedBytes)
	}
	if asOf == "" {
		return nil, "", fmt.Errorf("sync advisories: FIRST EPSS score date is missing")
	}
	return result, asOf, nil
}

func finiteUnit(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
}

func parseEPSSDate(header string) string {
	header = strings.ReplaceAll(strings.TrimSpace(strings.TrimPrefix(header, "#")), ",", " ")
	for _, field := range strings.Fields(header) {
		if strings.HasPrefix(field, "score_date:") {
			value := strings.TrimPrefix(field, "score_date:")
			if parsed, err := time.Parse(time.RFC3339, value); err == nil {
				return parsed.UTC().Format("2006-01-02")
			}
			if parsed, err := time.Parse("2006-01-02", value); err == nil {
				return parsed.Format("2006-01-02")
			}
		}
	}
	return ""
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			seen[strings.TrimSpace(value)] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
