package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishCreatesDeterministicInstallableBundle(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	signaturesDir := filepath.Join(directory, "signatures")
	if err := os.Mkdir(signaturesDir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	fixture := fixtureYAML(t, "example-affected-range.yaml")
	if err := os.WriteFile(filepath.Join(signaturesDir, "example.yaml"), fixture, 0o600); err != nil {
		t.Fatalf("WriteFile(signature) error = %v", err)
	}
	private := testKey(t)
	keyPath := writePublishPrivateKey(t, directory, private)
	firstDir := filepath.Join(directory, "bundle-one")
	secondDir := filepath.Join(directory, "bundle-two")

	first, err := Publish(context.Background(), PublishOptions{
		SignaturesDir: signaturesDir, OutputDir: firstDir, Version: "2026.08.27.1", SigningKeyPath: keyPath,
	})
	if err != nil {
		t.Fatalf("Publish(first) error = %v", err)
	}
	second, err := Publish(context.Background(), PublishOptions{
		SignaturesDir: signaturesDir, OutputDir: secondDir, Version: "2026.08.27.1", SigningKeyPath: keyPath,
	})
	if err != nil {
		t.Fatalf("Publish(second) error = %v", err)
	}
	if first.Version != "2026.08.27.1" || first.Files != 1 || first.KeyID == "" || second.KeyID != first.KeyID {
		t.Fatalf("publish results = %#v / %#v", first, second)
	}
	for _, name := range []string{ArchiveName, ManifestName, SignatureName} {
		firstContents, readErr := os.ReadFile(filepath.Join(firstDir, name))
		if readErr != nil {
			t.Fatalf("ReadFile(first/%s) error = %v", name, readErr)
		}
		secondContents, readErr := os.ReadFile(filepath.Join(secondDir, name))
		if readErr != nil {
			t.Fatalf("ReadFile(second/%s) error = %v", name, readErr)
		}
		if !bytes.Equal(firstContents, secondContents) {
			t.Errorf("published %s is not deterministic", name)
		}
	}

	destination := filepath.Join(directory, "installed")
	result, err := Apply(context.Background(), Options{
		Source: firstDir, Dir: destination, PublicKey: private.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatalf("Apply(published bundle) error = %v", err)
	}
	if result.Version != first.Version || result.Files != 1 {
		t.Fatalf("Apply() result = %#v", result)
	}
}

func TestPublishRejectsInvalidCorpusAndExistingOutput(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	signaturesDir := filepath.Join(directory, "signatures")
	if err := os.Mkdir(signaturesDir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(signaturesDir, "invalid.yaml"), []byte("id: invalid\nunknown: true\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	private := testKey(t)
	keyPath := writePublishPrivateKey(t, directory, private)
	_, err := Publish(context.Background(), PublishOptions{
		SignaturesDir: signaturesDir, OutputDir: filepath.Join(directory, "bundle"), Version: "v1", SigningKeyPath: keyPath,
	})
	if err == nil || !strings.Contains(err.Error(), "validate corpus") {
		t.Fatalf("Publish(invalid corpus) error = %v", err)
	}

	existing := filepath.Join(directory, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatalf("Mkdir(existing) error = %v", err)
	}
	_, err = Publish(context.Background(), PublishOptions{
		SignaturesDir: signaturesDir, OutputDir: existing, Version: "v1", SigningKeyPath: keyPath,
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Publish(existing) error = %v", err)
	}
}

func writePublishPrivateKey(t *testing.T, directory string, private ed25519.PrivateKey) string {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	path := filepath.Join(directory, "private.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}
	return path
}
