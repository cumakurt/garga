package evidence

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type VerifyOptions struct {
	BundlePath    string
	PublicKeyPath string
}

func Verify(ctx context.Context, options VerifyOptions) (Verification, error) {
	if err := ctx.Err(); err != nil {
		return Verification{}, err
	}
	if strings.TrimSpace(options.BundlePath) == "" {
		return Verification{}, fmt.Errorf("verify evidence: bundle path is required")
	}
	info, err := os.Lstat(options.BundlePath)
	if err != nil {
		return Verification{}, fmt.Errorf("verify evidence: inspect bundle: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Verification{}, fmt.Errorf("verify evidence: bundle must be a regular non-symlink file")
	}
	if info.Size() > MaxBundleBytes {
		return Verification{}, fmt.Errorf("verify evidence: bundle exceeds %d bytes", MaxBundleBytes)
	}

	bundle, err := os.Open(options.BundlePath)
	if err != nil {
		return Verification{}, fmt.Errorf("verify evidence: open bundle: %w", err)
	}
	defer bundle.Close()
	openedInfo, err := bundle.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != info.Size() {
		return Verification{}, fmt.Errorf("verify evidence: bundle changed while opening")
	}
	reader, err := zip.NewReader(bundle, openedInfo.Size())
	if err != nil {
		return Verification{}, fmt.Errorf("verify evidence: open ZIP: %w", err)
	}
	if len(reader.File) > MaxArtifacts+2 {
		return Verification{}, fmt.Errorf("verify evidence: ZIP contains too many entries")
	}
	entries := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		mode := file.Mode()
		if !mode.IsRegular() || mode&os.ModeSymlink != 0 || !validZipEntryName(file.Name) {
			return Verification{}, fmt.Errorf("verify evidence: ZIP entry name is invalid")
		}
		if _, exists := entries[file.Name]; exists {
			return Verification{}, fmt.Errorf("verify evidence: ZIP contains duplicate entries")
		}
		entries[file.Name] = file
	}

	manifestFile := entries["manifest.json"]
	if manifestFile == nil {
		return Verification{}, fmt.Errorf("verify evidence: manifest.json is missing")
	}
	manifestBytes, err := readZipEntry(manifestFile, maxManifestBytes)
	if err != nil {
		return Verification{}, fmt.Errorf("verify evidence: read manifest: %w", err)
	}
	manifest, err := decodeManifest(manifestBytes)
	if err != nil {
		return Verification{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return Verification{}, err
	}

	verification := Verification{
		SchemaVersion: SchemaVersion,
		Bundle:        filepath.Base(options.BundlePath),
		Artifacts:     len(manifest.Entries),
		Verified:      true,
	}
	expectedEntries := len(manifest.Entries) + 1
	if manifest.Signature != nil {
		expectedEntries++
		verification.Signed = true
		verification.KeyID = manifest.Signature.KeyID
	}
	if len(entries) != expectedEntries {
		return Verification{}, fmt.Errorf("verify evidence: ZIP contains undeclared entries")
	}

	for _, manifestEntry := range manifest.Entries {
		if err := ctx.Err(); err != nil {
			return Verification{}, err
		}
		file := entries["artifacts/"+manifestEntry.Name]
		if file == nil {
			return Verification{}, fmt.Errorf("verify evidence: artifact %q is missing", manifestEntry.Name)
		}
		uncompressedSize, sizeErr := zipEntrySize(file)
		if sizeErr != nil || uncompressedSize > MaxArtifactBytes || uncompressedSize != manifestEntry.Size {
			return Verification{}, fmt.Errorf("verify evidence: artifact %q size does not match manifest", manifestEntry.Name)
		}
		digest, size, err := hashZipEntry(file)
		if err != nil {
			return Verification{}, fmt.Errorf("verify evidence: read artifact %q: %w", manifestEntry.Name, err)
		}
		if size != manifestEntry.Size || digest != manifestEntry.SHA256 {
			return Verification{}, fmt.Errorf("verify evidence: artifact %q digest does not match manifest", manifestEntry.Name)
		}
		verification.Bytes += size
		if verification.Bytes > MaxTotalBytes {
			return Verification{}, fmt.Errorf("verify evidence: artifacts exceed %d total bytes", MaxTotalBytes)
		}
	}

	signatureFile := entries["manifest.sig"]
	if manifest.Signature == nil {
		if signatureFile != nil {
			return Verification{}, fmt.Errorf("verify evidence: undeclared signature entry")
		}
		if options.PublicKeyPath != "" {
			return Verification{}, fmt.Errorf("verify evidence: public key was provided for an unsigned bundle")
		}
		return verification, nil
	}
	if signatureFile == nil {
		return Verification{}, fmt.Errorf("verify evidence: manifest signature is missing")
	}
	if options.PublicKeyPath == "" {
		return Verification{}, fmt.Errorf("verify evidence: signed bundle requires a public key")
	}
	publicKey, err := loadPublicKey(options.PublicKeyPath)
	if err != nil {
		return Verification{}, err
	}
	if keyID(publicKey) != manifest.Signature.KeyID {
		return Verification{}, fmt.Errorf("verify evidence: public key ID does not match manifest")
	}
	signatureBytes, err := readZipEntry(signatureFile, 1024)
	if err != nil {
		return Verification{}, fmt.Errorf("verify evidence: read signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureBytes)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Verification{}, fmt.Errorf("verify evidence: signature encoding is invalid")
	}
	if !ed25519.Verify(publicKey, manifestBytes, signature) {
		return Verification{}, fmt.Errorf("verify evidence: manifest signature is invalid")
	}
	return verification, nil
}

func validZipEntryName(name string) bool {
	if name == "manifest.json" || name == "manifest.sig" {
		return true
	}
	if !strings.HasPrefix(name, "artifacts/") {
		return false
	}
	return validArtifactName(strings.TrimPrefix(name, "artifacts/"))
}

func readZipEntry(file *zip.File, limit int64) ([]byte, error) {
	size, err := zipEntrySize(file)
	if err != nil || size > limit {
		return nil, fmt.Errorf("entry exceeds %d bytes", limit)
	}
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	contents, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, fmt.Errorf("entry exceeds %d bytes", limit)
	}
	return contents, nil
}

func zipEntrySize(file *zip.File) (int64, error) {
	const maxInt64 = ^uint64(0) >> 1
	if file.UncompressedSize64 > maxInt64 {
		return 0, fmt.Errorf("ZIP entry size exceeds int64")
	}
	return int64(file.UncompressedSize64), nil
}

func hashZipEntry(file *zip.File) (string, int64, error) {
	reader, err := file.Open()
	if err != nil {
		return "", 0, err
	}
	defer reader.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(reader, MaxArtifactBytes+1))
	if err != nil {
		return "", 0, err
	}
	if size > MaxArtifactBytes {
		return "", 0, fmt.Errorf("artifact exceeds %d bytes", MaxArtifactBytes)
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func decodeManifest(contents []byte) (Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("verify evidence: manifest is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, fmt.Errorf("verify evidence: manifest has trailing content")
	}
	return manifest, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("verify evidence: manifest schema version is not supported")
	}
	if manifest.Algorithm != DigestAlgorithm {
		return fmt.Errorf("verify evidence: manifest digest algorithm is not supported")
	}
	if len(manifest.Entries) == 0 || len(manifest.Entries) > MaxArtifacts {
		return fmt.Errorf("verify evidence: manifest artifact count is invalid")
	}
	previousName := ""
	var total int64
	for _, entry := range manifest.Entries {
		if !validArtifactName(entry.Name) || entry.Name <= previousName {
			return fmt.Errorf("verify evidence: manifest artifact names are invalid or unsorted")
		}
		previousName = entry.Name
		if entry.Size < 0 || entry.Size > MaxArtifactBytes {
			return fmt.Errorf("verify evidence: manifest artifact size is invalid")
		}
		total += entry.Size
		if total > MaxTotalBytes {
			return fmt.Errorf("verify evidence: manifest total size is invalid")
		}
		digest, err := hex.DecodeString(entry.SHA256)
		if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != entry.SHA256 {
			return fmt.Errorf("verify evidence: manifest artifact digest is invalid")
		}
	}
	if manifest.Signature != nil {
		if manifest.Signature.Algorithm != SignatureAlgorithm {
			return fmt.Errorf("verify evidence: manifest signature algorithm is not supported")
		}
		key, err := hex.DecodeString(manifest.Signature.KeyID)
		if err != nil || len(key) != 16 || hex.EncodeToString(key) != manifest.Signature.KeyID {
			return fmt.Errorf("verify evidence: manifest key ID is invalid")
		}
	}
	return nil
}
