package update

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cumakurt/garga/internal/vulnerability"
)

func extractAndVerify(ctx context.Context, archive []byte, manifest Manifest, dest string) error {
	if int64(len(archive)) > MaxArchiveBytes {
		return fmt.Errorf("%w: archive exceeds the %d-byte limit", ErrArchive, MaxArchiveBytes)
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return fmt.Errorf("%w: archive is not a valid zip", ErrArchive)
	}
	if len(reader.File) != len(manifest.Files) {
		return fmt.Errorf("%w: archive file count does not match the manifest", ErrArchive)
	}

	expected := make(map[string]ManifestFile, len(manifest.Files))
	for _, file := range manifest.Files {
		expected[file.Name] = file
	}

	var uncompressed uint64
	seen := make(map[string]struct{}, len(reader.File))
	for _, entry := range reader.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		name, err := safeZipEntry(entry)
		if err != nil {
			return err
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("%w: archive contains duplicate file %q", ErrArchive, name)
		}
		seen[name] = struct{}{}
		meta, ok := expected[name]
		if !ok {
			return fmt.Errorf("%w: archive contains unexpected file %q", ErrArchive, name)
		}
		uncompressed += entry.UncompressedSize64
		if uncompressed > uint64(MaxArchiveBytes) {
			return fmt.Errorf("%w: uncompressed archive exceeds the %d-byte limit", ErrArchive, MaxArchiveBytes)
		}
		contents, err := readZipFile(entry)
		if err != nil {
			return err
		}
		if int64(len(contents)) != meta.Size || uint64(len(contents)) != entry.UncompressedSize64 {
			return fmt.Errorf("%w: archive file size does not match the manifest", ErrArchive)
		}
		if !sameChecksum(checksumSHA256(contents), meta.SHA256) {
			return fmt.Errorf("%w: archive file checksum does not match the manifest", ErrArchive)
		}
		path := filepath.Join(dest, name)
		if filepath.Dir(path) != dest {
			return fmt.Errorf("%w: archive entry escaped the staging directory", ErrArchive)
		}
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			return fmt.Errorf("write staged signature: %w", err)
		}
	}
	for name := range expected {
		if _, ok := seen[name]; !ok {
			return fmt.Errorf("%w: archive is missing %q", ErrArchive, name)
		}
	}
	return nil
}

func safeZipEntry(entry *zip.File) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("%w: archive entry is missing", ErrArchive)
	}
	info := entry.FileInfo()
	if info.IsDir() || strings.HasSuffix(entry.Name, "/") {
		return "", fmt.Errorf("%w: archive must not contain directories", ErrArchive)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: archive must not contain symlinks", ErrArchive)
	}
	if entry.UncompressedSize64 > uint64(vulnerability.MaxSignatureBytes) {
		return "", fmt.Errorf("%w: archive entry exceeds the signature size limit", ErrArchive)
	}
	return safeSignatureName(entry.Name)
}

func safeSignatureName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("%w: signature file name is not a safe basename", ErrArchive)
	}
	if name == "." || name == ".." {
		return "", fmt.Errorf("%w: signature file name is not a safe basename", ErrArchive)
	}
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".yaml" && ext != ".yml" {
		return "", fmt.Errorf("%w: signature file must be YAML", ErrArchive)
	}
	return name, nil
}

func readZipFile(entry *zip.File) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("%w: open archive entry", ErrArchive)
	}
	defer reader.Close()
	limit := int64(entry.UncompressedSize64)
	if limit < 1 {
		limit = 1
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read archive entry", ErrArchive)
	}
	if int64(len(data)) != int64(entry.UncompressedSize64) {
		return nil, fmt.Errorf("%w: archive entry size mismatch", ErrArchive)
	}
	return data, nil
}
