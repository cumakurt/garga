package update

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cumakurt/garga/internal/transport"
	"github.com/cumakurt/garga/internal/vulnerability"
)

// Options configure a signature-database update or rollback.
type Options struct {
	Source    string
	Dir       string
	PublicKey ed25519.PublicKey
	Client    *transport.Client
	Fetcher   Fetcher
}

// Result is the activated signature database version.
type Result struct {
	Version string
	Files   int
}

// Apply fetches, verifies, stages, and atomically activates a signature bundle.
func Apply(ctx context.Context, options Options) (result Result, err error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	dir, err := cleanDestination(options.Dir)
	if err != nil {
		return Result{}, err
	}
	key, err := publicKeyOrDefault(options.PublicKey)
	if err != nil {
		return Result{}, err
	}
	fetcher := options.Fetcher
	if fetcher == nil {
		fetcher, err = newFetcher(options.Source, options.Client)
		if err != nil {
			return Result{}, err
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{}, fmt.Errorf("create signature directory: %w", err)
	}
	if err := recoverDatabase(dir); err != nil {
		return Result{}, err
	}

	manifestBytes, err := fetcher.Fetch(ctx, ManifestName)
	if err != nil {
		return Result{}, err
	}
	signatureBytes, err := fetcher.Fetch(ctx, SignatureName)
	if err != nil {
		return Result{}, err
	}
	archiveBytes, err := fetcher.Fetch(ctx, ArchiveName)
	if err != nil {
		return Result{}, err
	}
	if err := VerifyManifest(key, manifestBytes, signatureBytes); err != nil {
		return Result{}, err
	}
	manifest, err := ParseManifest(manifestBytes)
	if err != nil {
		return Result{}, err
	}
	if !sameChecksum(checksumSHA256(archiveBytes), manifest.ArchiveSHA256) {
		return Result{}, fmt.Errorf("%w: archive checksum does not match the manifest", ErrVerification)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	staging, err := os.MkdirTemp(dir, stagingPrefix)
	if err != nil {
		return Result{}, fmt.Errorf("create signature staging directory: %w", err)
	}
	defer func() {
		if staging != "" {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := extractAndVerify(ctx, archiveBytes, manifest, staging); err != nil {
		return Result{}, err
	}
	if _, err := vulnerability.LoadDir(staging); err != nil {
		return Result{}, fmt.Errorf("%w: %s", ErrValidation, err.Error())
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := activate(dir, staging); err != nil {
		return Result{}, err
	}
	staging = ""
	return Result{Version: manifest.Version, Files: len(manifest.Files)}, nil
}

// Rollback restores the previous signature database, if one exists.
func Rollback(dir string) error {
	dir, err := cleanDestination(dir)
	if err != nil {
		return err
	}
	if err := recoverDatabase(dir); err != nil {
		return err
	}
	current := filepath.Join(dir, CurrentDir)
	previous := filepath.Join(dir, PreviousDir)
	if _, err := os.Lstat(previous); err != nil {
		return fmt.Errorf("%w: previous signature database is not available", ErrValidation)
	}
	swap := filepath.Join(dir, rollbackTempName)
	_ = os.RemoveAll(swap)
	if _, err := os.Lstat(current); err == nil {
		if err := os.Rename(current, swap); err != nil {
			return fmt.Errorf("rollback signatures: %w", err)
		}
	}
	if err := os.Rename(previous, current); err != nil {
		if _, swapErr := os.Lstat(swap); swapErr == nil {
			_ = os.Rename(swap, current)
		}
		return fmt.Errorf("rollback signatures: %w", err)
	}
	if _, err := os.Lstat(swap); err == nil {
		if err := os.Rename(swap, previous); err != nil {
			_ = os.RemoveAll(swap)
		}
	}
	return nil
}

func cleanDestination(dir string) (string, error) {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "" || dir == "." {
		return "", fmt.Errorf("update signatures: destination directory is required")
	}
	return dir, nil
}

func recoverDatabase(dir string) error {
	current := filepath.Join(dir, CurrentDir)
	previous := filepath.Join(dir, PreviousDir)
	next := filepath.Join(dir, nextDirName)
	_, currentErr := os.Lstat(current)
	_, nextErr := os.Lstat(next)
	if currentErr == nil {
		if nextErr == nil {
			_ = os.RemoveAll(next)
		}
		cleanupStaging(dir)
		return nil
	}
	if nextErr == nil {
		if err := os.Rename(next, current); err != nil {
			return fmt.Errorf("recover signature database: %w", err)
		}
		cleanupStaging(dir)
		return nil
	}
	if _, err := os.Lstat(previous); err == nil {
		if err := os.Rename(previous, current); err != nil {
			return fmt.Errorf("recover signature database: %w", err)
		}
	}
	cleanupStaging(dir)
	return nil
}

func activate(dir, staging string) error {
	current := filepath.Join(dir, CurrentDir)
	previous := filepath.Join(dir, PreviousDir)
	next := filepath.Join(dir, nextDirName)
	_ = os.RemoveAll(next)
	if err := os.Rename(staging, next); err != nil {
		return fmt.Errorf("stage signature database: %w", err)
	}
	if _, err := os.Lstat(current); err == nil {
		_ = os.RemoveAll(previous)
		if err := os.Rename(current, previous); err != nil {
			_ = os.RemoveAll(next)
			return fmt.Errorf("replace signature database: %w", err)
		}
	}
	if err := os.Rename(next, current); err != nil {
		if _, prevErr := os.Lstat(previous); prevErr == nil {
			_ = os.Rename(previous, current)
		}
		_ = os.RemoveAll(next)
		return fmt.Errorf("activate signature database: %w", err)
	}
	return nil
}

func cleanupStaging(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, stagingPrefix) || name == nextDirName || name == rollbackTempName {
			_ = os.RemoveAll(filepath.Join(dir, name))
		}
	}
}
