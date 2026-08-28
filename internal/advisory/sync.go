package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/vulnerability"
)

const (
	DefaultElasticCategoryURL = "https://discuss.elastic.co/c/announcements/security-announcements/31.json"
	DefaultCVEAPIBase         = "https://cveawg.mitre.org/api/cve/"
	DefaultKEVURL             = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL            = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	defaultMaxPages           = 50
	maxTopics                 = 2000
)

var (
	cvePattern      = regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4,}`)
	cveExactPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	esaPattern      = regexp.MustCompile(`ESA-[0-9]{4}-[0-9]+`)
)

type Options struct {
	SignatureDir       string
	CandidateDir       string
	ElasticCategoryURL string
	CVEAPIBase         string
	KEVURL             string
	EPSSURL            string
	MaxPages           int
	Fetcher            Fetcher
}

type elasticTopic struct {
	ID        int
	Slug      string
	Title     string
	CreatedAt string
	URL       string
	ESA       string
	CVEs      []string
}

func Sync(ctx context.Context, options Options) (Result, error) {
	options = defaultOptions(options)
	if strings.TrimSpace(options.SignatureDir) == "" {
		return Result{}, fmt.Errorf("sync advisories: signature directory is required")
	}
	existing, err := signatureInventory(options.SignatureDir)
	if err != nil {
		return Result{}, err
	}
	topics, err := fetchElasticTopics(ctx, options)
	if err != nil {
		return Result{}, err
	}
	discoveredCVEs := make(map[string]struct{})
	for _, topic := range topics {
		for _, cve := range topic.CVEs {
			discoveredCVEs[cve] = struct{}{}
		}
	}
	existingCVEs := make([]string, 0, len(existing))
	for cve := range existing {
		existingCVEs = append(existingCVEs, cve)
	}
	sort.Strings(existingCVEs)
	for _, cve := range existingCVEs {
		if _, discovered := discoveredCVEs[cve]; discovered {
			continue
		}
		topics = append(topics, elasticTopic{
			CVEs: []string{cve}, URL: "https://nvd.nist.gov/vuln/detail/" + cve,
		})
	}
	desiredCVEs := make(map[string]struct{})
	for _, topic := range topics {
		for _, cve := range topic.CVEs {
			desiredCVEs[cve] = struct{}{}
		}
	}
	kev, err := fetchKEV(ctx, options.Fetcher, options.KEVURL)
	if err != nil {
		return Result{}, err
	}
	epss, asOf, err := fetchEPSS(ctx, options.Fetcher, options.EPSSURL, desiredCVEs)
	if err != nil {
		return Result{}, err
	}

	advisories := make([]Advisory, 0)
	seen := make(map[string]struct{})
	for _, topic := range topics {
		for _, cve := range topic.CVEs {
			if _, duplicate := seen[cve]; duplicate {
				continue
			}
			seen[cve] = struct{}{}
			record, recordErr := fetchCVERecord(ctx, options.Fetcher, options.CVEAPIBase, cve)
			if recordErr != nil {
				return Result{}, recordErr
			}
			item := advisoryFromRecord(topic, record)
			item.SignatureFilename, item.SignaturePresent = existing[cve]
			item.KnownExploited = kev[cve]
			item.ThreatUpdated = asOf
			if score, ok := epss[cve]; ok {
				item.EPSS = floatPointer(score.Score)
				item.EPSSPercentile = floatPointer(score.Percentile)
			}
			if item.SignaturePresent {
				item.CandidateStatus = "present"
			} else {
				item.CandidateStatus = "ready"
				contents, candidateErr := marshalCandidate(item)
				if candidateErr != nil {
					item.CandidateStatus = "blocked"
					item.CandidateReason = candidateErr.Error()
				} else if _, candidateErr = vulnerability.Parse(strings.ToLower(item.CVE)+".yaml", contents); candidateErr != nil {
					item.CandidateStatus = "blocked"
					item.CandidateReason = record.CandidateReason
					if item.CandidateReason == "" {
						item.CandidateReason = "CVE record cannot be converted into a valid Elasticsearch signature"
					}
				}
			}
			advisories = append(advisories, item)
		}
	}
	sort.Slice(advisories, func(left, right int) bool { return advisories[left].CVE < advisories[right].CVE })
	snapshot := Snapshot{
		SchemaVersion: SchemaVersion,
		AsOf:          asOf,
		Sources: Sources{
			Elastic: options.ElasticCategoryURL, CVE: options.CVEAPIBase, CISAKEV: options.KEVURL, EPSS: options.EPSSURL,
		},
		Advisories: advisories,
	}
	for _, item := range advisories {
		switch item.CandidateStatus {
		case "present":
			snapshot.Summary.Present++
		case "ready":
			snapshot.Summary.Ready++
		default:
			snapshot.Summary.Blocked++
		}
	}
	snapshot.Summary.Advisories = len(advisories)
	result := Result{Snapshot: snapshot}
	if options.CandidateDir != "" {
		written, writeErr := WriteCandidates(options.CandidateDir, advisories)
		if writeErr != nil {
			return Result{}, writeErr
		}
		result.WrittenCandidates = written
	}
	return result, nil
}

func defaultOptions(options Options) Options {
	if options.ElasticCategoryURL == "" {
		options.ElasticCategoryURL = DefaultElasticCategoryURL
	}
	if options.CVEAPIBase == "" {
		options.CVEAPIBase = DefaultCVEAPIBase
	}
	if options.KEVURL == "" {
		options.KEVURL = DefaultKEVURL
	}
	if options.EPSSURL == "" {
		options.EPSSURL = DefaultEPSSURL
	}
	if options.MaxPages == 0 {
		options.MaxPages = defaultMaxPages
	}
	if options.Fetcher == nil {
		options.Fetcher = HTTPFetcher{}
	}
	return options
}

func signatureInventory(directory string) (map[string]string, error) {
	if _, err := vulnerability.LoadDir(directory); err != nil {
		return nil, fmt.Errorf("sync advisories: validate signature corpus: %w", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("sync advisories: read signature corpus: %w", err)
	}
	result := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		extension := strings.ToLower(filepath.Ext(name))
		if extension != ".yaml" && extension != ".yml" {
			continue
		}
		contents, err := readSignatureFile(directory, name)
		if err != nil {
			return nil, fmt.Errorf("sync advisories: read signature %q: %w", name, err)
		}
		signature, err := vulnerability.Parse(name, contents)
		if err != nil {
			return nil, fmt.Errorf("sync advisories: %w", err)
		}
		for _, cve := range signature.CVE {
			result[cve] = name
		}
	}
	return result, nil
}

func fetchElasticTopics(ctx context.Context, options Options) ([]elasticTopic, error) {
	if options.MaxPages < 1 || options.MaxPages > defaultMaxPages {
		return nil, fmt.Errorf("sync advisories: max pages must be between 1 and %d", defaultMaxPages)
	}
	categoryURL, err := url.Parse(options.ElasticCategoryURL)
	if err != nil || categoryURL.Host == "" {
		return nil, fmt.Errorf("sync advisories: Elastic category URL is invalid")
	}
	next := categoryURL.String()
	topicByID := make(map[int]elasticTopic)
	for pageNumber := 0; pageNumber < options.MaxPages && next != ""; pageNumber++ {
		contents, err := options.Fetcher.Get(ctx, next, maxElasticPageBytes)
		if err != nil {
			return nil, fmt.Errorf("sync advisories: fetch Elastic category page %d: %w", pageNumber+1, err)
		}
		var document elasticCategoryDocument
		if err := decodeStrictJSON(contents, &document); err != nil {
			return nil, fmt.Errorf("sync advisories: Elastic category response is invalid")
		}
		for _, topic := range document.TopicList.Topics {
			if !strings.Contains(strings.ToLower(strings.TrimSpace(topic.Title)), "elasticsearch") ||
				!strings.Contains(strings.ToLower(topic.Title), "security update") {
				continue
			}
			if len(topicByID) >= maxTopics {
				return nil, fmt.Errorf("sync advisories: Elastic topic count exceeds %d", maxTopics)
			}
			topicByID[topic.ID] = elasticTopic{ID: topic.ID, Slug: topic.Slug, Title: topic.Title, CreatedAt: topic.CreatedAt}
		}
		if document.TopicList.MoreTopicsURL == "" {
			next = ""
			continue
		}
		resolved, resolveErr := categoryURL.Parse(document.TopicList.MoreTopicsURL)
		if resolveErr == nil && !strings.HasSuffix(resolved.Path, ".json") {
			resolved.Path += ".json"
		}
		if resolveErr != nil || resolved.Scheme != categoryURL.Scheme || resolved.Host != categoryURL.Host {
			return nil, fmt.Errorf("sync advisories: Elastic pagination URL is invalid")
		}
		next = resolved.String()
	}
	if next != "" {
		return nil, fmt.Errorf("sync advisories: Elastic pagination exceeds %d pages", options.MaxPages)
	}

	topics := make([]elasticTopic, 0, len(topicByID))
	for _, topic := range topicByID {
		topics = append(topics, topic)
	}
	sort.Slice(topics, func(left, right int) bool { return topics[left].ID < topics[right].ID })
	for index := range topics {
		detailURL := *categoryURL
		detailURL.Path = "/t/" + strconv.Itoa(topics[index].ID) + ".json"
		detailURL.RawQuery = ""
		contents, err := options.Fetcher.Get(ctx, detailURL.String(), maxTopicBytes)
		if err != nil {
			return nil, fmt.Errorf("sync advisories: fetch Elastic topic %d: %w", topics[index].ID, err)
		}
		var document elasticTopicDocument
		if err := decodeStrictJSON(contents, &document); err != nil || len(document.PostStream.Posts) == 0 {
			return nil, fmt.Errorf("sync advisories: Elastic topic %d response is invalid", topics[index].ID)
		}
		text := topics[index].Title + "\n" + document.PostStream.Posts[0].Cooked
		topics[index].CVEs = uniqueMatches(cvePattern, text)
		if len(topics[index].CVEs) == 0 {
			return nil, fmt.Errorf("sync advisories: Elasticsearch security topic %d contains no CVE ID", topics[index].ID)
		}
		esas := uniqueMatches(esaPattern, text)
		if len(esas) > 0 {
			topics[index].ESA = esas[0]
		}
		topics[index].URL = categoryURL.Scheme + "://" + categoryURL.Host + "/t/" + topics[index].Slug + "/" + strconv.Itoa(topics[index].ID)
	}
	return topics, nil
}

func uniqueMatches(pattern *regexp.Regexp, value string) []string {
	seen := make(map[string]struct{})
	for _, match := range pattern.FindAllString(strings.ToUpper(value), -1) {
		seen[match] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for match := range seen {
		result = append(result, match)
	}
	sort.Strings(result)
	return result
}

func decodeStrictJSON(contents []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("JSON contains trailing content")
	}
	return nil
}

func floatPointer(value float64) *float64 {
	return &value
}

func parseTimestamp(value string) string {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return ""
	}
	return parsed.UTC().Format(time.RFC3339)
}
