package update

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/cumakurt/garga/internal/vulnerability"
)

// Manifest describes one signed signature archive.
type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	Version       string         `json:"version"`
	ArchiveSHA256 string         `json:"archive_sha256"`
	Files         []ManifestFile `json:"files"`
}

// ManifestFile is one YAML signature inside the archive.
type ManifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ParseManifest decodes a verified manifest document.
func ParseManifest(data []byte) (Manifest, error) {
	if len(data) > maxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: manifest exceeds the %d-byte limit", ErrVerification, maxManifestBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("%w: manifest is not a valid JSON object", ErrVerification)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return Manifest{}, fmt.Errorf("%w: manifest must contain exactly one JSON value", ErrVerification)
	}
	if manifest.SchemaVersion != "0.1" {
		return Manifest{}, fmt.Errorf("%w: manifest schema_version is not supported", ErrVerification)
	}
	if strings.TrimSpace(manifest.Version) == "" {
		return Manifest{}, fmt.Errorf("%w: manifest version is required", ErrVerification)
	}
	archiveSum, err := normalizeSHA256(manifest.ArchiveSHA256)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: archive checksum is invalid", ErrVerification)
	}
	manifest.ArchiveSHA256 = archiveSum
	if len(manifest.Files) == 0 {
		return Manifest{}, fmt.Errorf("%w: manifest files are required", ErrVerification)
	}
	if len(manifest.Files) > vulnerability.MaxSignatureFiles {
		return Manifest{}, fmt.Errorf("%w: manifest exceeds %d files", ErrVerification, vulnerability.MaxSignatureFiles)
	}
	seen := make(map[string]struct{}, len(manifest.Files))
	for index, file := range manifest.Files {
		name, nameErr := safeSignatureName(file.Name)
		if nameErr != nil {
			return Manifest{}, nameErr
		}
		if _, exists := seen[name]; exists {
			return Manifest{}, fmt.Errorf("%w: manifest lists duplicate file %q", ErrVerification, name)
		}
		seen[name] = struct{}{}
		sum, sumErr := normalizeSHA256(file.SHA256)
		if sumErr != nil {
			return Manifest{}, fmt.Errorf("%w: file checksum is invalid", ErrVerification)
		}
		if file.Size < 1 || file.Size > int64(vulnerability.MaxSignatureBytes) {
			return Manifest{}, fmt.Errorf("%w: file size is invalid", ErrVerification)
		}
		manifest.Files[index].Name = name
		manifest.Files[index].SHA256 = sum
	}
	return manifest, nil
}

func checksumSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func normalizeSHA256(value string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("invalid sha256")
	}
	return hex.EncodeToString(raw), nil
}

func sameChecksum(got, want string) bool {
	left, leftErr := hex.DecodeString(got)
	right, rightErr := hex.DecodeString(want)
	if leftErr != nil || rightErr != nil || len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare(left, right) == 1
}
