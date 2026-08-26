package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/cumakurt/garga/internal/cli"
)

var (
	version = "dev"
	commit  = "none"
	builtAt = "unknown"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	exitCode := cli.Execute(ctx, os.Args[1:], cli.BuildInfo{
		Version: version,
		Commit:  commit,
		BuiltAt: builtAt,
	}, os.Stdin, os.Stdout, os.Stderr)
	os.Exit(exitCode)
}
