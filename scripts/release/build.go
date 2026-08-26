package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func produce(cfg config) error {
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	sbomPath, err := writeSBOM(cfg)
	if err != nil {
		return err
	}
	var artifacts []string
	for _, plat := range releasePlatforms {
		archivePath, err := buildPlatform(cfg, plat, sbomPath)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", plat.GOOS, plat.GOARCH, err)
		}
		artifacts = append(artifacts, archivePath)
	}
	artifacts = append(artifacts, sbomPath)
	sumsPath, err := writeChecksums(cfg.OutDir, artifacts)
	if err != nil {
		return err
	}
	if err := maybeSign(cfg, sumsPath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "release: wrote %s\n", cfg.OutDir)
	return nil
}

func buildPlatform(cfg config, plat platform, sbomPath string) (string, error) {
	work, err := os.MkdirTemp("", "garga-release-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)

	binaryPath := filepath.Join(work, cfg.binaryName(plat))
	command := exec.Command(cfg.GoBin, "build",
		"-trimpath",
		"-buildvcs=false",
		"-ldflags", cfg.ldflags(),
		"-o", binaryPath,
		"./cmd/garga",
	)
	command.Dir = cfg.Root
	command.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+plat.GOOS,
		"GOARCH="+plat.GOARCH,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go build: %w\n%s", err, strings.TrimSpace(string(output)))
	}

	prefix := cfg.archiveBase(plat)
	files, err := archiveFiles(cfg, plat, binaryPath, sbomPath)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(cfg.OutDir, prefix+"."+plat.Format)
	switch plat.Format {
	case "tar.gz":
		if err := writeTarGz(dest, prefix, files, cfg.BuiltAt); err != nil {
			return "", err
		}
	case "zip":
		if err := writeZip(dest, prefix, files, cfg.BuiltAt); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unsupported archive format %q", plat.Format)
	}
	return dest, nil
}

type archiveFile struct {
	Name string
	Path string
	Mode os.FileMode
}

func archiveFiles(cfg config, plat platform, binaryPath, sbomPath string) ([]archiveFile, error) {
	files := []archiveFile{
		{Name: cfg.binaryName(plat), Path: binaryPath, Mode: 0o755},
		{Name: "LICENSE", Path: filepath.Join(cfg.Root, "LICENSE"), Mode: 0o644},
		{Name: "README.md", Path: filepath.Join(cfg.Root, "README.md"), Mode: 0o644},
		{Name: "SECURITY.md", Path: filepath.Join(cfg.Root, "SECURITY.md"), Mode: 0o644},
		{Name: "CHANGELOG.md", Path: filepath.Join(cfg.Root, "CHANGELOG.md"), Mode: 0o644},
		{Name: "docs/responsible-use.md", Path: filepath.Join(cfg.Root, "docs", "responsible-use.md"), Mode: 0o644},
		{Name: "docs/release.md", Path: filepath.Join(cfg.Root, "docs", "release.md"), Mode: 0o644},
		{Name: "sbom.spdx.json", Path: sbomPath, Mode: 0o644},
	}
	metadata := filepath.Join(filepath.Dir(binaryPath), "release-metadata.txt")
	if err := os.WriteFile(metadata, []byte(releaseMetadata(cfg, plat)), 0o644); err != nil {
		return nil, err
	}
	files = append(files, archiveFile{Name: "release-metadata.txt", Path: metadata, Mode: 0o644})
	for _, file := range files {
		if _, err := os.Stat(file.Path); err != nil {
			return nil, fmt.Errorf("archive member %s: %w", file.Name, err)
		}
	}
	return files, nil
}

func releaseMetadata(cfg config, plat platform) string {
	return fmt.Sprintf(
		"name=%s\nmodule=%s\nversion=%s\ncommit=%s\nbuilt_at=%s\ngoos=%s\ngoarch=%s\n",
		binaryName,
		modulePath,
		cfg.Version,
		cfg.Commit,
		cfg.BuiltAt.Format("2006-01-02T15:04:05Z07:00"),
		plat.GOOS,
		plat.GOARCH,
	)
}
