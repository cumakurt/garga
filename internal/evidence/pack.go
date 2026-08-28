package evidence

import (
	"archive/zip"
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
	"sort"
	"strings"
	"time"
)

type PackOptions struct {
	Paths          []string
	OutputPath     string
	SigningKeyPath string
}

type artifact struct {
	entry Entry
	file  *os.File
}

var zipTimestamp = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

func Pack(ctx context.Context, options PackOptions) (manifest Manifest, err error) {
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	if len(options.Paths) == 0 {
		return Manifest{}, fmt.Errorf("pack evidence: at least one artifact is required")
	}
	if len(options.Paths) > MaxArtifacts {
		return Manifest{}, fmt.Errorf("pack evidence: artifact count exceeds %d", MaxArtifacts)
	}
	if strings.TrimSpace(options.OutputPath) == "" {
		return Manifest{}, fmt.Errorf("pack evidence: output path is required")
	}
	if _, statErr := os.Lstat(options.OutputPath); statErr == nil {
		return Manifest{}, fmt.Errorf("pack evidence: output already exists")
	} else if !os.IsNotExist(statErr) {
		return Manifest{}, fmt.Errorf("pack evidence: inspect output: %w", statErr)
	}

	artifacts, loadErr := loadArtifacts(ctx, options.Paths)
	if loadErr != nil {
		return Manifest{}, loadErr
	}
	defer func() {
		for _, item := range artifacts {
			if closeErr := item.file.Close(); closeErr != nil && err == nil {
				err = fmt.Errorf("pack evidence: close artifact: %w", closeErr)
			}
		}
	}()

	manifest = Manifest{
		SchemaVersion: SchemaVersion,
		Algorithm:     DigestAlgorithm,
		Entries:       make([]Entry, 0, len(artifacts)),
	}
	for _, item := range artifacts {
		manifest.Entries = append(manifest.Entries, item.entry)
	}
	var privateKey ed25519.PrivateKey
	if options.SigningKeyPath != "" {
		privateKey, err = loadPrivateKey(options.SigningKeyPath)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Signature = &SignatureMetadata{
			Algorithm: SignatureAlgorithm,
			KeyID:     keyID(privateKey.Public().(ed25519.PublicKey)),
		}
	}
	manifestBytes, err := marshalManifest(manifest)
	if err != nil {
		return Manifest{}, fmt.Errorf("pack evidence: encode manifest: %w", err)
	}

	outputDirectory := filepath.Dir(options.OutputPath)
	temporary, err := os.CreateTemp(outputDirectory, ".garga-evidence-*.tmp")
	if err != nil {
		return Manifest{}, fmt.Errorf("pack evidence: create temporary bundle: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return Manifest{}, fmt.Errorf("pack evidence: secure temporary bundle: %w", err)
	}

	zipWriter := zip.NewWriter(temporary)
	for _, item := range artifacts {
		if err := ctx.Err(); err != nil {
			_ = zipWriter.Close()
			return Manifest{}, err
		}
		if err := writeZipArtifact(zipWriter, item); err != nil {
			_ = zipWriter.Close()
			return Manifest{}, err
		}
	}
	if err := writeZipBytes(zipWriter, "manifest.json", manifestBytes); err != nil {
		_ = zipWriter.Close()
		return Manifest{}, err
	}
	if privateKey != nil {
		signature := ed25519.Sign(privateKey, manifestBytes)
		encoded := []byte(base64.StdEncoding.EncodeToString(signature) + "\n")
		if err := writeZipBytes(zipWriter, "manifest.sig", encoded); err != nil {
			_ = zipWriter.Close()
			return Manifest{}, err
		}
	}
	if err := zipWriter.Close(); err != nil {
		return Manifest{}, fmt.Errorf("pack evidence: close ZIP: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return Manifest{}, fmt.Errorf("pack evidence: sync bundle: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return Manifest{}, fmt.Errorf("pack evidence: close bundle: %w", err)
	}
	if err := os.Link(temporaryPath, options.OutputPath); err != nil {
		return Manifest{}, fmt.Errorf("pack evidence: publish bundle without overwrite: %w", err)
	}
	return manifest, nil
}

func loadArtifacts(ctx context.Context, paths []string) ([]artifact, error) {
	artifacts := make([]artifact, 0, len(paths))
	seenNames := make(map[string]struct{}, len(paths))
	var total int64
	cleanup := func() {
		for _, item := range artifacts {
			_ = item.file.Close()
		}
	}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			cleanup()
			return nil, err
		}
		name := filepath.Base(filepath.Clean(path))
		if path == "" || !validArtifactName(name) {
			cleanup()
			return nil, fmt.Errorf("pack evidence: artifact name is invalid")
		}
		if _, exists := seenNames[name]; exists {
			cleanup()
			return nil, fmt.Errorf("pack evidence: artifact names must be unique")
		}
		seenNames[name] = struct{}{}

		linkInfo, err := os.Lstat(path)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("pack evidence: inspect artifact %q: %w", name, err)
		}
		if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
			cleanup()
			return nil, fmt.Errorf("pack evidence: artifact %q must be a regular non-symlink file", name)
		}
		file, err := os.Open(path)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("pack evidence: open artifact %q: %w", name, err)
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || !os.SameFile(linkInfo, info) {
			_ = file.Close()
			cleanup()
			return nil, fmt.Errorf("pack evidence: artifact %q changed while opening", name)
		}
		if info.Size() > MaxArtifactBytes {
			_ = file.Close()
			cleanup()
			return nil, fmt.Errorf("pack evidence: artifact %q exceeds %d bytes", name, MaxArtifactBytes)
		}
		total += info.Size()
		if total > MaxTotalBytes {
			_ = file.Close()
			cleanup()
			return nil, fmt.Errorf("pack evidence: artifacts exceed %d total bytes", MaxTotalBytes)
		}
		hash := sha256.New()
		count, err := io.Copy(hash, io.LimitReader(file, MaxArtifactBytes+1))
		if err != nil || count != info.Size() {
			_ = file.Close()
			cleanup()
			return nil, fmt.Errorf("pack evidence: read artifact %q", name)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			_ = file.Close()
			cleanup()
			return nil, fmt.Errorf("pack evidence: rewind artifact %q: %w", name, err)
		}
		artifacts = append(artifacts, artifact{
			entry: Entry{Name: name, Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))},
			file:  file,
		})
	}
	sort.Slice(artifacts, func(left, right int) bool {
		return artifacts[left].entry.Name < artifacts[right].entry.Name
	})
	return artifacts, nil
}

func validArtifactName(name string) bool {
	return name != "" && name != "." && name != ".." && name == filepath.Base(name) && !strings.ContainsAny(name, "/\\\x00")
}

func marshalManifest(manifest Manifest) ([]byte, error) {
	contents, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(contents, '\n'), nil
}

func writeZipArtifact(writer *zip.Writer, item artifact) error {
	header := &zip.FileHeader{Name: "artifacts/" + item.entry.Name, Method: zip.Deflate}
	header.Modified = zipTimestamp
	header.SetMode(0o600)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("pack evidence: create ZIP artifact %q: %w", item.entry.Name, err)
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(entry, hash), io.LimitReader(item.file, item.entry.Size+1))
	if err != nil || written != item.entry.Size {
		return fmt.Errorf("pack evidence: write ZIP artifact %q", item.entry.Name)
	}
	if hex.EncodeToString(hash.Sum(nil)) != item.entry.SHA256 {
		return fmt.Errorf("pack evidence: artifact %q changed while packaging", item.entry.Name)
	}
	return nil
}

func writeZipBytes(writer *zip.Writer, name string, contents []byte) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.Modified = zipTimestamp
	header.SetMode(0o600)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("pack evidence: create ZIP entry %q: %w", name, err)
	}
	if _, err := entry.Write(contents); err != nil {
		return fmt.Errorf("pack evidence: write ZIP entry %q: %w", name, err)
	}
	return nil
}
