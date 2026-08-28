package update

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cumakurt/garga/internal/signing"
	"github.com/cumakurt/garga/internal/vulnerability"
)

var publishVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type PublishOptions struct {
	SignaturesDir  string
	OutputDir      string
	Version        string
	SigningKeyPath string
}

type PublishResult struct {
	Version   string `json:"version"`
	Files     int    `json:"files"`
	KeyID     string `json:"key_id"`
	OutputDir string `json:"output_dir"`
}

type publishFile struct {
	name     string
	contents []byte
}

func Publish(ctx context.Context, options PublishOptions) (PublishResult, error) {
	if err := ctx.Err(); err != nil {
		return PublishResult{}, err
	}
	if !publishVersionPattern.MatchString(strings.TrimSpace(options.Version)) {
		return PublishResult{}, fmt.Errorf("publish signatures: version must contain 1-64 letters, digits, dots, underscores, or hyphens")
	}
	if strings.TrimSpace(options.SignaturesDir) == "" {
		return PublishResult{}, fmt.Errorf("publish signatures: signature directory is required")
	}
	outputDir := filepath.Clean(strings.TrimSpace(options.OutputDir))
	if outputDir == "" || outputDir == "." || outputDir == string(filepath.Separator) {
		return PublishResult{}, fmt.Errorf("publish signatures: output directory is required")
	}
	if strings.TrimSpace(options.SigningKeyPath) == "" {
		return PublishResult{}, fmt.Errorf("publish signatures: signing key is required")
	}
	if _, err := os.Lstat(outputDir); err == nil {
		return PublishResult{}, fmt.Errorf("publish signatures: output directory already exists")
	} else if !os.IsNotExist(err) {
		return PublishResult{}, fmt.Errorf("publish signatures: inspect output directory: %w", err)
	}

	files, err := loadPublishFiles(ctx, options.SignaturesDir)
	if err != nil {
		return PublishResult{}, err
	}
	privateKey, err := signing.LoadPrivateKey(options.SigningKeyPath)
	if err != nil {
		return PublishResult{}, err
	}
	archiveBytes, manifestFiles, err := buildSignatureArchive(ctx, files)
	if err != nil {
		return PublishResult{}, err
	}
	manifest := Manifest{
		SchemaVersion: "0.1",
		Version:       strings.TrimSpace(options.Version),
		ArchiveSHA256: checksumSHA256(archiveBytes),
		Files:         manifestFiles,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return PublishResult{}, fmt.Errorf("publish signatures: encode manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	signatureBytes := []byte(hex.EncodeToString(ed25519.Sign(privateKey, manifestBytes)) + "\n")

	parent := filepath.Dir(outputDir)
	staging, err := os.MkdirTemp(parent, ".garga-signatures-*.tmp")
	if err != nil {
		return PublishResult{}, fmt.Errorf("publish signatures: create staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	outputs := []publishFile{
		{name: ArchiveName, contents: archiveBytes},
		{name: ManifestName, contents: manifestBytes},
		{name: SignatureName, contents: signatureBytes},
	}
	for _, output := range outputs {
		if err := writePublishedFile(filepath.Join(staging, output.name), output.contents); err != nil {
			return PublishResult{}, err
		}
	}
	if err := os.Rename(staging, outputDir); err != nil {
		return PublishResult{}, fmt.Errorf("publish signatures: activate output directory: %w", err)
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)
	return PublishResult{
		Version: manifest.Version, Files: len(files), KeyID: signing.KeyID(publicKey), OutputDir: outputDir,
	}, nil
}

func loadPublishFiles(ctx context.Context, directory string) ([]publishFile, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("publish signatures: inspect signature directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("publish signatures: signature path must be a non-symlink directory")
	}
	if _, err := vulnerability.LoadDir(directory); err != nil {
		return nil, fmt.Errorf("publish signatures: validate corpus: %w", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("publish signatures: read signature directory: %w", err)
	}
	files := make([]publishFile, 0, len(entries))
	seenIDs := make(map[string]string, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name()
		extension := strings.ToLower(filepath.Ext(name))
		if strings.HasPrefix(name, ".") || (extension != ".yaml" && extension != ".yml") {
			continue
		}
		if _, err := safeSignatureName(name); err != nil {
			return nil, fmt.Errorf("publish signatures: %w", err)
		}
		path := filepath.Join(directory, name)
		fileInfo, err := os.Lstat(path)
		if err != nil || fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("publish signatures: signature %q must be a regular non-symlink file", name)
		}
		if fileInfo.Size() < 1 || fileInfo.Size() > vulnerability.MaxSignatureBytes {
			return nil, fmt.Errorf("publish signatures: signature %q size is invalid", name)
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("publish signatures: open signature %q: %w", name, err)
		}
		openedInfo, statErr := file.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(fileInfo, openedInfo) {
			_ = file.Close()
			return nil, fmt.Errorf("publish signatures: signature %q changed while reading", name)
		}
		contents, readErr := io.ReadAll(io.LimitReader(file, vulnerability.MaxSignatureBytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			return nil, fmt.Errorf("publish signatures: read signature %q", name)
		}
		if int64(len(contents)) != openedInfo.Size() {
			return nil, fmt.Errorf("publish signatures: signature %q changed while reading", name)
		}
		signature, parseErr := vulnerability.Parse(name, contents)
		if parseErr != nil {
			return nil, fmt.Errorf("publish signatures: validate read signature: %w", parseErr)
		}
		if previous, exists := seenIDs[signature.ID]; exists {
			return nil, fmt.Errorf("publish signatures: signature %q reuses id %q from %q", name, signature.ID, previous)
		}
		seenIDs[signature.ID] = name
		files = append(files, publishFile{name: name, contents: contents})
	}
	sort.Slice(files, func(left, right int) bool { return files[left].name < files[right].name })
	return files, nil
}

func buildSignatureArchive(ctx context.Context, files []publishFile) ([]byte, []ManifestFile, error) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	manifestFiles := make([]ManifestFile, 0, len(files))
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			_ = writer.Close()
			return nil, nil, err
		}
		header := &zip.FileHeader{Name: file.name, Method: zip.Deflate}
		header.Modified = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)
		header.SetMode(0o600)
		entry, err := writer.CreateHeader(header)
		if err != nil {
			_ = writer.Close()
			return nil, nil, fmt.Errorf("publish signatures: create archive entry %q: %w", file.name, err)
		}
		if _, err := entry.Write(file.contents); err != nil {
			_ = writer.Close()
			return nil, nil, fmt.Errorf("publish signatures: write archive entry %q: %w", file.name, err)
		}
		manifestFiles = append(manifestFiles, ManifestFile{
			Name: file.name, SHA256: checksumSHA256(file.contents), Size: int64(len(file.contents)),
		})
	}
	if err := writer.Close(); err != nil {
		return nil, nil, fmt.Errorf("publish signatures: close archive: %w", err)
	}
	if archive.Len() > MaxArchiveBytes {
		return nil, nil, fmt.Errorf("publish signatures: archive exceeds %d bytes", MaxArchiveBytes)
	}
	return archive.Bytes(), manifestFiles, nil
}

func writePublishedFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("publish signatures: create %q: %w", filepath.Base(path), err)
	}
	if _, err := io.Copy(file, bytes.NewReader(contents)); err != nil {
		_ = file.Close()
		return fmt.Errorf("publish signatures: write %q: %w", filepath.Base(path), err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("publish signatures: sync %q: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("publish signatures: close %q: %w", filepath.Base(path), err)
	}
	return nil
}
