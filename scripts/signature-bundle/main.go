// Command signature-bundle creates an installable signed vulnerability corpus.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/cumakurt/garga/internal/update"
)

func main() {
	var (
		signatures = flag.String("signatures", "internal/vulnerability/bundled", "validated YAML signature directory")
		output     = flag.String("out", "", "new output directory")
		version    = flag.String("version", "", "corpus version")
		key        = flag.String("key", "", "Ed25519 private key")
	)
	flag.Parse()
	result, err := update.Publish(context.Background(), update.PublishOptions{
		SignaturesDir:  *signatures,
		OutputDir:      *output,
		Version:        *version,
		SigningKeyPath: *key,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "signature-bundle: %v\n", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "signature-bundle: write result: %v\n", err)
		os.Exit(1)
	}
}
