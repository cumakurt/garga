package update

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cumakurt/garga/internal/config"
	"github.com/cumakurt/garga/internal/transport"
)

func TestApplyActivatesVerifiedBundle(t *testing.T) {
	t.Parallel()

	private := testKey(t)
	source := t.TempDir()
	dest := t.TempDir()
	yamlFile := fixtureYAML(t, "example-affected-range.yaml")
	writeSignedBundle(t, source, private, "2026.08.26.1", map[string][]byte{
		"example-affected-range.yaml": yamlFile,
	})

	result, err := Apply(context.Background(), Options{
		Source:    source,
		Dir:       dest,
		PublicKey: private.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Version != "2026.08.26.1" || result.Files != 1 {
		t.Fatalf("result = %#v", result)
	}
	got := currentFile(t, dest, "example-affected-range.yaml")
	if !bytes.Equal(got, yamlFile) {
		t.Fatal("activated file does not match the bundle")
	}
}

func TestApplyRejectsTamperedArchiveAndLeavesCurrent(t *testing.T) {
	t.Parallel()

	private := testKey(t)
	source := t.TempDir()
	dest := t.TempDir()
	original := []byte("keep-me")
	seedCurrent(t, dest, "kept.yaml", original)
	writeSignedBundle(t, source, private, "tamper", map[string][]byte{
		"example-affected-range.yaml": fixtureYAML(t, "example-affected-range.yaml"),
	})
	archivePath := filepath.Join(source, ArchiveName)
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	archive[len(archive)-1] ^= 0xff
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err = Apply(context.Background(), Options{
		Source:    source,
		Dir:       dest,
		PublicKey: private.Public().(ed25519.PublicKey),
	})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Apply() error = %v, want ErrVerification", err)
	}
	if !bytes.Equal(currentFile(t, dest, "kept.yaml"), original) {
		t.Fatal("tampered update changed the active database")
	}
}

func TestApplyRejectsWrongTrustRoot(t *testing.T) {
	t.Parallel()

	private := testKey(t)
	other := testKey(t)
	source := t.TempDir()
	writeSignedBundle(t, source, private, "v1", map[string][]byte{
		"example-affected-range.yaml": fixtureYAML(t, "example-affected-range.yaml"),
	})
	_, err := Apply(context.Background(), Options{
		Source:    source,
		Dir:       t.TempDir(),
		PublicKey: other.Public().(ed25519.PublicKey),
	})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Apply() error = %v, want ErrVerification", err)
	}
}

func TestApplyRejectsZipSlipAndSymlink(t *testing.T) {
	t.Parallel()

	private := testKey(t)
	yamlFile := fixtureYAML(t, "example-affected-range.yaml")

	t.Run("parent path", func(t *testing.T) {
		t.Parallel()
		source := t.TempDir()
		dest := t.TempDir()
		seedCurrent(t, dest, "kept.yaml", []byte("keep-me"))
		writeMaliciousZip(t, source, private, "../escape.yaml", "ok.yaml", yamlFile, false)
		_, err := Apply(context.Background(), Options{
			Source:    source,
			Dir:       dest,
			PublicKey: private.Public().(ed25519.PublicKey),
		})
		if !errors.Is(err, ErrArchive) && !errors.Is(err, ErrVerification) {
			t.Fatalf("Apply() error = %v, want archive or verification failure", err)
		}
		if !bytes.Equal(currentFile(t, dest, "kept.yaml"), []byte("keep-me")) {
			t.Fatal("zip-slip update changed the active database")
		}
		if _, err := os.Lstat(filepath.Join(dest, "escape.yaml")); err == nil {
			t.Fatal("zip-slip wrote a file outside current/")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		t.Parallel()
		source := t.TempDir()
		dest := t.TempDir()
		seedCurrent(t, dest, "kept.yaml", []byte("keep-me"))
		writeMaliciousZip(t, source, private, "link.yaml", "link.yaml", yamlFile, true)
		_, err := Apply(context.Background(), Options{
			Source:    source,
			Dir:       dest,
			PublicKey: private.Public().(ed25519.PublicKey),
		})
		if !errors.Is(err, ErrArchive) && !errors.Is(err, ErrVerification) {
			t.Fatalf("Apply() error = %v, want archive or verification failure", err)
		}
		if !bytes.Equal(currentFile(t, dest, "kept.yaml"), []byte("keep-me")) {
			t.Fatal("symlink update changed the active database")
		}
	})
}

func TestApplyRejectsInvalidSignaturesBeforeActivation(t *testing.T) {
	t.Parallel()

	private := testKey(t)
	source := t.TempDir()
	dest := t.TempDir()
	seedCurrent(t, dest, "kept.yaml", []byte("keep-me"))
	invalid, err := os.ReadFile(filepath.Join("..", "vulnerability", "testdata", "invalid", "unknown-field.yaml"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	writeSignedBundle(t, source, private, "bad", map[string][]byte{"unknown-field.yaml": invalid})
	_, err = Apply(context.Background(), Options{
		Source:    source,
		Dir:       dest,
		PublicKey: private.Public().(ed25519.PublicKey),
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("Apply() error = %v, want ErrValidation", err)
	}
	if !bytes.Equal(currentFile(t, dest, "kept.yaml"), []byte("keep-me")) {
		t.Fatal("invalid signatures changed the active database")
	}
}

func TestApplyHonorsCancellationBeforeActivation(t *testing.T) {
	t.Parallel()

	private := testKey(t)
	source := t.TempDir()
	dest := t.TempDir()
	seedCurrent(t, dest, "kept.yaml", []byte("keep-me"))
	writeSignedBundle(t, source, private, "cancel", map[string][]byte{
		"example-affected-range.yaml": fixtureYAML(t, "example-affected-range.yaml"),
	})
	ctx, cancel := context.WithCancel(context.Background())
	inner, err := newFetcher(source, nil)
	if err != nil {
		t.Fatalf("newFetcher() error = %v", err)
	}
	_, err = Apply(ctx, Options{
		Dir:       dest,
		PublicKey: private.Public().(ed25519.PublicKey),
		Fetcher: cancelAfterArchive{
			inner:  inner,
			cancel: cancel,
		},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply() error = %v, want canceled", err)
	}
	if !bytes.Equal(currentFile(t, dest, "kept.yaml"), []byte("keep-me")) {
		t.Fatal("canceled update changed the active database")
	}
}

func TestApplyAndRollbackReplacePrevious(t *testing.T) {
	t.Parallel()

	private := testKey(t)
	dest := t.TempDir()
	first := fixtureYAML(t, "example-affected-range.yaml")
	second := fixtureYAML(t, "example-prerelease.yaml")

	source1 := t.TempDir()
	writeSignedBundle(t, source1, private, "v1", map[string][]byte{"example-affected-range.yaml": first})
	if _, err := Apply(context.Background(), Options{
		Source:    source1,
		Dir:       dest,
		PublicKey: private.Public().(ed25519.PublicKey),
	}); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}

	source2 := t.TempDir()
	writeSignedBundle(t, source2, private, "v2", map[string][]byte{"example-prerelease.yaml": second})
	if _, err := Apply(context.Background(), Options{
		Source:    source2,
		Dir:       dest,
		PublicKey: private.Public().(ed25519.PublicKey),
	}); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	if !bytes.Equal(currentFile(t, dest, "example-prerelease.yaml"), second) {
		t.Fatal("second apply did not activate v2")
	}

	if err := Rollback(dest); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if !bytes.Equal(currentFile(t, dest, "example-affected-range.yaml"), first) {
		t.Fatal("rollback did not restore v1")
	}
}

func TestApplyHTTPBundle(t *testing.T) {
	t.Parallel()

	private := testKey(t)
	source := t.TempDir()
	writeSignedBundle(t, source, private, "http-1", map[string][]byte{
		"example-affected-range.yaml": fixtureYAML(t, "example-affected-range.yaml"),
	})
	server := httptest.NewServer(http.FileServer(http.Dir(source)))
	t.Cleanup(server.Close)

	client := testClient(t)
	result, err := Apply(context.Background(), Options{
		Source:    server.URL + "/",
		Dir:       t.TempDir(),
		PublicKey: private.Public().(ed25519.PublicKey),
		Client:    client,
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Version != "http-1" {
		t.Fatalf("version = %q", result.Version)
	}
}

func TestDefaultPublicKeyRejectsUnsignedBundle(t *testing.T) {
	t.Parallel()

	private := testKey(t)
	source := t.TempDir()
	writeSignedBundle(t, source, private, "v1", map[string][]byte{
		"example-affected-range.yaml": fixtureYAML(t, "example-affected-range.yaml"),
	})
	_, err := Apply(context.Background(), Options{Source: source, Dir: t.TempDir()})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Apply() error = %v, want ErrVerification", err)
	}
}

func writeMaliciousZip(t *testing.T, dest string, private ed25519.PrivateKey, zipName, listedName string, contents []byte, symlink bool) {
	t.Helper()
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	header := &zip.FileHeader{Name: zipName, Method: zip.Deflate}
	if symlink {
		header.SetMode(os.ModeSymlink | 0o777)
	}
	entry, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatalf("CreateHeader() error = %v", err)
	}
	if _, err := entry.Write(contents); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	zipBytes := archive.Bytes()
	manifest := Manifest{
		SchemaVersion: "0.1",
		Version:       "evil",
		ArchiveSHA256: checksumSHA256(zipBytes),
		Files: []ManifestFile{{
			Name:   listedName,
			SHA256: checksumSHA256(contents),
			Size:   int64(len(contents)),
		}},
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

type cancelAfterArchive struct {
	inner  Fetcher
	cancel context.CancelFunc
}

func (fetcher cancelAfterArchive) Fetch(ctx context.Context, name string) ([]byte, error) {
	data, err := fetcher.inner.Fetch(ctx, name)
	if name == ArchiveName {
		fetcher.cancel()
	}
	return data, err
}

func testClient(t *testing.T) *transport.Client {
	t.Helper()
	options, err := transport.OptionsFromConfig(config.Defaults(), "garga/update-test")
	if err != nil {
		t.Fatalf("OptionsFromConfig() error = %v", err)
	}
	options.MaxResponseBytes = MaxArchiveBytes
	factory, err := transport.NewFactory(options)
	if err != nil {
		t.Fatalf("NewFactory() error = %v", err)
	}
	t.Cleanup(factory.CloseIdleConnections)
	return factory.Client()
}
