package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	modulePath     = "github.com/cumakurt/garga"
	binaryName     = "garga"
	ldflagsVersion = "main.version"
	ldflagsCommit  = "main.commit"
	ldflagsBuiltAt = "main.builtAt"
)

var versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)

type getenvFunc func(string) string

type options struct {
	Version string
	Commit  string
	OutDir  string
	BuiltAt string
	Root    string
}

type platform struct {
	GOOS      string
	GOARCH    string
	Extension string
	Format    string
}

var releasePlatforms = []platform{
	{GOOS: "linux", GOARCH: "amd64", Format: "tar.gz"},
	{GOOS: "linux", GOARCH: "arm64", Format: "tar.gz"},
	{GOOS: "darwin", GOARCH: "amd64", Format: "tar.gz"},
	{GOOS: "darwin", GOARCH: "arm64", Format: "tar.gz"},
	{GOOS: "windows", GOARCH: "amd64", Extension: ".exe", Format: "zip"},
}

type config struct {
	Root    string
	OutDir  string
	Version string
	Commit  string
	BuiltAt time.Time
	GoBin   string
}

func resolveConfig(opts options, getenv getenvFunc, now func() time.Time) (config, error) {
	root := strings.TrimSpace(opts.Root)
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return config{}, fmt.Errorf("working directory: %w", err)
		}
		root, err = findModuleRoot(wd)
		if err != nil {
			return config{}, err
		}
	}
	version := strings.TrimSpace(opts.Version)
	if version == "" {
		version = strings.TrimSpace(getenv("GARGA_RELEASE_VERSION"))
	}
	if version == "" {
		return config{}, fmt.Errorf("version is required (flag -version or GARGA_RELEASE_VERSION)")
	}
	if version != "dev" && !versionPattern.MatchString(version) {
		return config{}, fmt.Errorf("version %q is not a semantic version", version)
	}

	commit := strings.TrimSpace(opts.Commit)
	if commit == "" {
		commit = strings.TrimSpace(getenv("GARGA_RELEASE_COMMIT"))
	}
	if commit == "" {
		detected, err := gitHEAD(root)
		if err != nil {
			commit = "none"
		} else {
			commit = detected
		}
	}

	builtAt, err := parseBuiltAt(opts.BuiltAt, getenv, now)
	if err != nil {
		return config{}, err
	}

	outDir := strings.TrimSpace(opts.OutDir)
	if outDir == "" {
		outDir = "dist"
	}
	if !filepath.IsAbs(outDir) {
		outDir = filepath.Join(root, outDir)
	}

	goBin := strings.TrimSpace(getenv("GO"))
	if goBin == "" {
		goBin = "go"
	}

	return config{
		Root:    root,
		OutDir:  outDir,
		Version: version,
		Commit:  commit,
		BuiltAt: builtAt.UTC().Truncate(time.Second),
		GoBin:   goBin,
	}, nil
}

func parseBuiltAt(raw string, getenv getenvFunc, now func() time.Time) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return time.Time{}, fmt.Errorf("built-at: %w", err)
		}
		return parsed, nil
	}
	if epoch := strings.TrimSpace(getenv("SOURCE_DATE_EPOCH")); epoch != "" {
		seconds, err := strconv.ParseInt(epoch, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH: %w", err)
		}
		return time.Unix(seconds, 0), nil
	}
	return now(), nil
}

func findModuleRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %s", start)
		}
		dir = parent
	}
}

func gitHEAD(root string) (string, error) {
	command := exec.Command("git", "rev-parse", "HEAD")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func (cfg config) archiveBase(plat platform) string {
	return fmt.Sprintf("%s_%s_%s_%s", binaryName, cfg.Version, plat.GOOS, plat.GOARCH)
}

func (cfg config) binaryName(plat platform) string {
	return binaryName + plat.Extension
}

func (cfg config) ldflags() string {
	return fmt.Sprintf("-s -w -X %s=%s -X %s=%s -X %s=%s",
		ldflagsVersion, cfg.Version,
		ldflagsCommit, cfg.Commit,
		ldflagsBuiltAt, cfg.BuiltAt.Format(time.RFC3339),
	)
}
