// Command advisory-sync audits official advisories and prepares a signed-corpus input.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cumakurt/garga/internal/advisory"
)

type commandResult struct {
	Snapshot   advisory.Snapshot      `json:"snapshot"`
	Candidates []string               `json:"candidates,omitempty"`
	Corpus     *advisory.CorpusResult `json:"corpus,omitempty"`
}

func main() {
	var (
		signatures        = flag.String("signatures", "internal/vulnerability/bundled", "existing validated signature directory")
		candidates        = flag.String("candidates", "", "new directory for reviewable missing signature candidates")
		corpusOutput      = flag.String("corpus-out", "", "new directory for the enriched complete corpus")
		includeCandidates = flag.Bool("include-candidates", false, "include safely generated missing signatures in corpus-out")
		snapshotPath      = flag.String("snapshot", "", "write audit JSON to a new file instead of stdout")
		elasticURL        = flag.String("elastic-url", advisory.DefaultElasticCategoryURL, "Elastic Security Announcements category JSON URL")
		cveURL            = flag.String("cve-url", advisory.DefaultCVEAPIBase, "CVE Services API base URL")
		kevURL            = flag.String("kev-url", advisory.DefaultKEVURL, "CISA KEV JSON URL")
		epssURL           = flag.String("epss-url", advisory.DefaultEPSSURL, "FIRST EPSS current CSV gzip URL")
		maxPages          = flag.Int("max-pages", 50, "maximum Elastic category pages")
	)
	flag.Parse()
	result, err := advisory.Sync(context.Background(), advisory.Options{
		SignatureDir:       *signatures,
		CandidateDir:       *candidates,
		ElasticCategoryURL: *elasticURL,
		CVEAPIBase:         *cveURL,
		KEVURL:             *kevURL,
		EPSSURL:            *epssURL,
		MaxPages:           *maxPages,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "advisory-sync: %v\n", err)
		os.Exit(1)
	}
	output := commandResult{Snapshot: result.Snapshot, Candidates: result.WrittenCandidates}
	if *corpusOutput != "" {
		corpus, buildErr := advisory.BuildCorpus(*signatures, *corpusOutput, result.Snapshot.Advisories, *includeCandidates)
		if buildErr != nil {
			fmt.Fprintf(os.Stderr, "advisory-sync: %v\n", buildErr)
			os.Exit(1)
		}
		output.Corpus = &corpus
	}
	writer, closer, err := outputWriter(*snapshotPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "advisory-sync: %v\n", err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		_ = closer()
		fmt.Fprintf(os.Stderr, "advisory-sync: write snapshot: %v\n", err)
		os.Exit(1)
	}
	if err := closer(); err != nil {
		fmt.Fprintf(os.Stderr, "advisory-sync: close snapshot: %v\n", err)
		os.Exit(1)
	}
	remainingReady := result.Snapshot.Summary.Ready
	if *corpusOutput != "" && *includeCandidates {
		remainingReady = 0
	}
	if result.Snapshot.Summary.Blocked > 0 || remainingReady > 0 {
		fmt.Fprintf(
			os.Stderr,
			"advisory-sync: corpus incomplete: %d ready candidates and %d blocked advisories\n",
			remainingReady,
			result.Snapshot.Summary.Blocked,
		)
		os.Exit(3)
	}
}

func outputWriter(path string) (io.Writer, func() error, error) {
	if path == "" || path == "-" {
		return os.Stdout, func() error { return nil }, nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, func() error { return nil }, fmt.Errorf("create snapshot: %w", err)
	}
	return file, file.Close, nil
}
