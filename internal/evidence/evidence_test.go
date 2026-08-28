package evidence

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPackAndVerifyUnsignedBundleDeterministically(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	reportPath := filepath.Join(directory, "report.pdf")
	findingsPath := filepath.Join(directory, "findings.jsonl")
	writeEvidenceFile(t, reportPath, []byte("deterministic PDF bytes\n"), 0o600)
	writeEvidenceFile(t, findingsPath, []byte(`{"check_id":"garga.test"}`+"\n"), 0o600)

	firstPath := filepath.Join(directory, "first.zip")
	secondPath := filepath.Join(directory, "second.zip")
	first, err := Pack(context.Background(), PackOptions{
		Paths: []string{reportPath, findingsPath}, OutputPath: firstPath,
	})
	if err != nil {
		t.Fatalf("Pack(first) error = %v", err)
	}
	second, err := Pack(context.Background(), PackOptions{
		Paths: []string{findingsPath, reportPath}, OutputPath: secondPath,
	})
	if err != nil {
		t.Fatalf("Pack(second) error = %v", err)
	}
	if len(first.Entries) != 2 || first.Entries[0].Name != "findings.jsonl" || second.Entries[0].Name != "findings.jsonl" {
		t.Fatalf("manifest entries are not sorted: %#v / %#v", first.Entries, second.Entries)
	}
	firstBytes, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatalf("ReadFile(first) error = %v", err)
	}
	secondBytes, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatalf("ReadFile(second) error = %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("Pack() output is not deterministic")
	}

	verified, err := Verify(context.Background(), VerifyOptions{BundlePath: firstPath})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !verified.Verified || verified.Signed || verified.Artifacts != 2 || verified.Bytes == 0 {
		t.Fatalf("verification = %#v", verified)
	}
}

func TestPackAndVerifySignedBundle(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "assessment.pdf")
	privatePath := filepath.Join(directory, "private.pem")
	publicPath := filepath.Join(directory, "public.pem")
	wrongPublicPath := filepath.Join(directory, "wrong-public.pem")
	writeEvidenceFile(t, artifactPath, []byte("assessment"), 0o600)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	writeKeyPair(t, privatePath, publicPath, privateKey, publicKey)
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(wrong) error = %v", err)
	}
	writePublicKey(t, wrongPublicPath, wrongPublic)

	bundlePath := filepath.Join(directory, "signed.zip")
	manifest, err := Pack(context.Background(), PackOptions{
		Paths: []string{artifactPath}, OutputPath: bundlePath, SigningKeyPath: privatePath,
	})
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	if manifest.Signature == nil || manifest.Signature.KeyID != keyID(publicKey) {
		t.Fatalf("manifest signature = %#v", manifest.Signature)
	}
	verified, err := Verify(context.Background(), VerifyOptions{BundlePath: bundlePath, PublicKeyPath: publicPath})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !verified.Signed || verified.KeyID != keyID(publicKey) {
		t.Fatalf("verification = %#v", verified)
	}
	if _, err := Verify(context.Background(), VerifyOptions{BundlePath: bundlePath}); err == nil || !strings.Contains(err.Error(), "requires a public key") {
		t.Fatalf("Verify(no key) error = %v", err)
	}
	if _, err := Verify(context.Background(), VerifyOptions{BundlePath: bundlePath, PublicKeyPath: wrongPublicPath}); err == nil || !strings.Contains(err.Error(), "key ID") {
		t.Fatalf("Verify(wrong key) error = %v", err)
	}
}

func TestVerifyRejectsTamperedArtifact(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "report.pdf")
	bundlePath := filepath.Join(directory, "bundle.zip")
	tamperedPath := filepath.Join(directory, "tampered.zip")
	writeEvidenceFile(t, artifactPath, []byte("original"), 0o600)
	if _, err := Pack(context.Background(), PackOptions{Paths: []string{artifactPath}, OutputPath: bundlePath}); err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	rewriteBundleEntry(t, bundlePath, tamperedPath, "artifacts/report.pdf", []byte("tampered"))
	if _, err := Verify(context.Background(), VerifyOptions{BundlePath: tamperedPath}); err == nil || !strings.Contains(err.Error(), "digest does not match") {
		t.Fatalf("Verify(tampered) error = %v", err)
	}
}

func TestVerifyRejectsSymlinkArchiveEntry(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "report.pdf")
	bundlePath := filepath.Join(directory, "bundle.zip")
	symlinkPath := filepath.Join(directory, "symlink-entry.zip")
	writeEvidenceFile(t, artifactPath, []byte("report"), 0o600)
	if _, err := Pack(context.Background(), PackOptions{Paths: []string{artifactPath}, OutputPath: bundlePath}); err != nil {
		t.Fatalf("Pack() error = %v", err)
	}
	rewriteBundleMode(t, bundlePath, symlinkPath, "artifacts/report.pdf", os.ModeSymlink|0o777)
	if _, err := Verify(context.Background(), VerifyOptions{BundlePath: symlinkPath}); err == nil || !strings.Contains(err.Error(), "entry name is invalid") {
		t.Fatalf("Verify(symlink entry) error = %v", err)
	}
}

func TestPackRejectsDuplicateNamesSymlinksAndExistingOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permission behavior differs on Windows")
	}

	directory := t.TempDir()
	firstDirectory := filepath.Join(directory, "first")
	secondDirectory := filepath.Join(directory, "second")
	if err := os.MkdirAll(firstDirectory, 0o700); err != nil {
		t.Fatalf("MkdirAll(first) error = %v", err)
	}
	if err := os.MkdirAll(secondDirectory, 0o700); err != nil {
		t.Fatalf("MkdirAll(second) error = %v", err)
	}
	first := filepath.Join(firstDirectory, "report.pdf")
	second := filepath.Join(secondDirectory, "report.pdf")
	writeEvidenceFile(t, first, []byte("first"), 0o600)
	writeEvidenceFile(t, second, []byte("second"), 0o600)
	if _, err := Pack(context.Background(), PackOptions{
		Paths: []string{first, second}, OutputPath: filepath.Join(directory, "duplicates.zip"),
	}); err == nil || !strings.Contains(err.Error(), "unique") {
		t.Fatalf("Pack(duplicates) error = %v", err)
	}

	symlink := filepath.Join(directory, "link.pdf")
	if err := os.Symlink(first, symlink); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := Pack(context.Background(), PackOptions{
		Paths: []string{symlink}, OutputPath: filepath.Join(directory, "symlink.zip"),
	}); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("Pack(symlink) error = %v", err)
	}

	existing := filepath.Join(directory, "existing.zip")
	writeEvidenceFile(t, existing, []byte("keep"), 0o600)
	if _, err := Pack(context.Background(), PackOptions{Paths: []string{first}, OutputPath: existing}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Pack(existing) error = %v", err)
	}
	contents, err := os.ReadFile(existing)
	if err != nil || string(contents) != "keep" {
		t.Fatalf("existing output changed: %q / %v", contents, err)
	}
}

func TestPackRejectsPermissivePrivateKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are not enforced on Windows")
	}
	t.Parallel()

	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "report.pdf")
	privatePath := filepath.Join(directory, "private.pem")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	writeEvidenceFile(t, artifactPath, []byte("report"), 0o600)
	writeKeyPair(t, privatePath, filepath.Join(directory, "public.pem"), privateKey, publicKey)
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	_, err = Pack(context.Background(), PackOptions{
		Paths: []string{artifactPath}, OutputPath: filepath.Join(directory, "bundle.zip"), SigningKeyPath: privatePath,
	})
	if err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("Pack(permissive key) error = %v", err)
	}
}

func writeEvidenceFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func writeKeyPair(t *testing.T, privatePath, publicPath string, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) {
	t.Helper()
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	writeEvidenceFile(t, privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	writePublicKey(t, publicPath, publicKey)
}

func writePublicKey(t *testing.T, path string, publicKey ed25519.PublicKey) {
	t.Helper()
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	writeEvidenceFile(t, path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
}

func rewriteBundleEntry(t *testing.T, sourcePath, targetPath, targetName string, replacement []byte) {
	t.Helper()
	source, err := zip.OpenReader(sourcePath)
	if err != nil {
		t.Fatalf("OpenReader() error = %v", err)
	}
	defer source.Close()
	target, err := os.Create(targetPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	writer := zip.NewWriter(target)
	for _, file := range source.File {
		entry, err := writer.Create(file.Name)
		if err != nil {
			t.Fatalf("Create(%s) error = %v", file.Name, err)
		}
		if file.Name == targetName {
			if _, err := entry.Write(replacement); err != nil {
				t.Fatalf("Write(replacement) error = %v", err)
			}
			continue
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatalf("Open(%s) error = %v", file.Name, err)
		}
		if _, err := io.Copy(entry, reader); err != nil {
			_ = reader.Close()
			t.Fatalf("Copy(%s) error = %v", file.Name, err)
		}
		if err := reader.Close(); err != nil {
			t.Fatalf("Close(%s) error = %v", file.Name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close(zip) error = %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("Close(target) error = %v", err)
	}
}

func rewriteBundleMode(t *testing.T, sourcePath, targetPath, targetName string, mode os.FileMode) {
	t.Helper()
	source, err := zip.OpenReader(sourcePath)
	if err != nil {
		t.Fatalf("OpenReader() error = %v", err)
	}
	defer source.Close()
	target, err := os.Create(targetPath)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	writer := zip.NewWriter(target)
	for _, file := range source.File {
		header := &zip.FileHeader{Name: file.Name, Method: zip.Deflate}
		header.SetMode(0o600)
		if file.Name == targetName {
			header.SetMode(mode)
		}
		entry, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("CreateHeader(%s) error = %v", file.Name, err)
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatalf("Open(%s) error = %v", file.Name, err)
		}
		if _, err := io.Copy(entry, reader); err != nil {
			_ = reader.Close()
			t.Fatalf("Copy(%s) error = %v", file.Name, err)
		}
		if err := reader.Close(); err != nil {
			t.Fatalf("Close(%s) error = %v", file.Name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close(zip) error = %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("Close(target) error = %v", err)
	}
}
