// Command release builds signed-ready garga distribution archives.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	var (
		version = flag.String("version", "", "release version (for example v0.1.0)")
		commit  = flag.String("commit", "", "source revision; defaults to git HEAD")
		outDir  = flag.String("out", "dist", "output directory for archives and checksums")
		builtAt = flag.String("built-at", "", "RFC3339 build timestamp; defaults to SOURCE_DATE_EPOCH or now")
	)
	flag.Parse()
	if err := run(options{
		Version: *version,
		Commit:  *commit,
		OutDir:  *outDir,
		BuiltAt: *builtAt,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "release: %v\n", err)
		os.Exit(1)
	}
}

func run(opts options) error {
	cfg, err := resolveConfig(opts, os.Getenv, time.Now)
	if err != nil {
		return err
	}
	return produce(cfg)
}
