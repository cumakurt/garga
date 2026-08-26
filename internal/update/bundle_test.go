package update

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return private
}

func fixtureYAML(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "vulnerability", "testdata", "valid", name))
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", name, err)
	}
	return data
}

func writeSignedBundle(t *testing.T, dest string, private ed25519.PrivateKey, version string, files map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	manifestFiles := make([]ManifestFile, 0, len(names))
	for _, name := range names {
		contents := files[name]
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("Create(%s) error = %v", name, err)
		}
		if _, err := entry.Write(contents); err != nil {
			t.Fatalf("Write(%s) error = %v", name, err)
		}
		manifestFiles = append(manifestFiles, ManifestFile{
			Name:   name,
			SHA256: checksumSHA256(contents),
			Size:   int64(len(contents)),
		})
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close zip error = %v", err)
	}
	zipBytes := archive.Bytes()
	manifest := Manifest{
		SchemaVersion: "0.1",
		Version:       version,
		ArchiveSHA256: checksumSHA256(zipBytes),
		Files:         manifestFiles,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, ManifestName), raw, 0o600); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}
	signature := hex.EncodeToString(ed25519.Sign(private, raw))
	if err := os.WriteFile(filepath.Join(dest, SignatureName), []byte(signature+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(signature) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, ArchiveName), zipBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(archive) error = %v", err)
	}
}

func seedCurrent(t *testing.T, dir, name string, contents []byte) {
	t.Helper()
	current := filepath.Join(dir, CurrentDir)
	if err := os.MkdirAll(current, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(current, name), contents, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func currentFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, CurrentDir, name))
	if err != nil {
		t.Fatalf("ReadFile(current/%s) error = %v", name, err)
	}
	return data
}
