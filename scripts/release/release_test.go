package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveConfigRequiresVersion(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	_, err := resolveConfig(options{Root: root, OutDir: t.TempDir()}, func(string) string { return "" }, time.Now)
	if err == nil {
		t.Fatal("expected version error")
	}
}

func TestResolveConfigRejectsInvalidVersion(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	_, err := resolveConfig(options{Version: "not a version", Root: root, OutDir: t.TempDir()}, getenvEmpty, time.Now)
	if err == nil {
		t.Fatal("expected invalid version error")
	}
}

func TestParseBuiltAtFromSourceDateEpoch(t *testing.T) {
	t.Parallel()
	parsed, err := parseBuiltAt("", func(key string) string {
		if key == "SOURCE_DATE_EPOCH" {
			return "1700000000"
		}
		return ""
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Unix() != 1700000000 {
		t.Fatalf("unix = %d", parsed.Unix())
	}
}

func TestProduceWritesArchivesChecksumsAndSBOM(t *testing.T) {
	root := moduleRoot(t)
	out := t.TempDir()
	cfg, err := resolveConfig(options{
		Version: "v0.0.0-test",
		Commit:  "testhash",
		OutDir:  out,
		Root:    root,
		BuiltAt: "2026-08-26T00:00:00Z",
	}, getenvEmpty, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := produce(cfg); err != nil {
		t.Fatal(err)
	}

	linuxArchive := filepath.Join(out, "garga_v0.0.0-test_linux_amd64.tar.gz")
	windowsArchive := filepath.Join(out, "garga_v0.0.0-test_windows_amd64.zip")
	sbomPath := filepath.Join(out, "garga_v0.0.0-test.spdx.json")
	sumsPath := filepath.Join(out, "SHA256SUMS")
	for _, path := range []string{
		linuxArchive,
		filepath.Join(out, "garga_v0.0.0-test_linux_arm64.tar.gz"),
		filepath.Join(out, "garga_v0.0.0-test_darwin_amd64.tar.gz"),
		filepath.Join(out, "garga_v0.0.0-test_darwin_arm64.tar.gz"),
		windowsArchive,
		sbomPath,
		sumsPath,
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
	}

	members := tarMembers(t, linuxArchive)
	for _, name := range []string{
		"garga_v0.0.0-test_linux_amd64/garga",
		"garga_v0.0.0-test_linux_amd64/LICENSE",
		"garga_v0.0.0-test_linux_amd64/README.md",
		"garga_v0.0.0-test_linux_amd64/SECURITY.md",
		"garga_v0.0.0-test_linux_amd64/CHANGELOG.md",
		"garga_v0.0.0-test_linux_amd64/docs/responsible-use.md",
		"garga_v0.0.0-test_linux_amd64/docs/release.md",
		"garga_v0.0.0-test_linux_amd64/sbom.spdx.json",
		"garga_v0.0.0-test_linux_amd64/release-metadata.txt",
	} {
		if !members[name] {
			t.Fatalf("archive missing %s", name)
		}
	}

	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sums), "garga_v0.0.0-test_linux_amd64.tar.gz") {
		t.Fatalf("checksums missing linux archive: %s", sums)
	}
	want, err := sha256File(linuxArchive)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sums), want) {
		t.Fatalf("checksums missing digest %s", want)
	}

	var document spdxDocument
	body, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	if document.SPDXVersion != "SPDX-2.3" {
		t.Fatalf("spdxVersion = %q", document.SPDXVersion)
	}
	if len(document.Relationships) != 1 || document.Relationships[0] != (spdxRelationship{
		ElementID: "SPDXRef-DOCUMENT", Type: "DESCRIBES", RelatedElement: "SPDXRef-Package-0",
	}) {
		t.Fatalf("document relationship = %#v", document.Relationships)
	}
	var sawCobra, sawMain bool
	for _, pkg := range document.Packages {
		if pkg.FilesAnalyzed {
			t.Fatalf("package %q unexpectedly claims file analysis", pkg.Name)
		}
		if pkg.Name == "github.com/spf13/cobra" {
			sawCobra = true
		}
		if pkg.Name == modulePath && pkg.LicenseConcluded == "AGPL-3.0-only" && pkg.VersionInfo == "v0.0.0-test" {
			sawMain = true
		}
	}
	if !sawCobra || !sawMain {
		t.Fatalf("sbom missing cobra or main package: cobra=%t main=%t", sawCobra, sawMain)
	}
}

func getenvEmpty(string) string { return "" }

func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := findModuleRoot(wd)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func tarMembers(t *testing.T, path string) map[string]bool {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	reader := tar.NewReader(gzipReader)
	members := map[string]bool{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return members
		}
		if err != nil {
			t.Fatal(err)
		}
		members[header.Name] = true
	}
}
