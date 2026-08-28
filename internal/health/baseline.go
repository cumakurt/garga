package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	healthmodel "github.com/cumakurt/garga/internal/health/model"
)

const maxBaselineBytes = 16 * 1024 * 1024

func LoadBaseline(path string) (*healthmodel.Baseline, error) {
	baseline, _, err := LoadBaselineBounded(path, maxBaselineBytes)
	return baseline, err
}

// LoadBaselineBounded reads a regular non-symlink baseline through a caller-provided
// byte budget and reports the bytes charged to that budget.
func LoadBaselineBounded(path string, limit int64) (*healthmodel.Baseline, int64, error) {
	if limit <= 0 {
		return nil, 0, fmt.Errorf("health baseline byte budget is exhausted")
	}
	if limit > maxBaselineBytes {
		limit = maxBaselineBytes
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, 0, fmt.Errorf("inspect health baseline: %w", err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("health baseline must be a regular non-symlink file")
	}
	if linkInfo.Size() > limit {
		return nil, 0, fmt.Errorf("health baseline exceeds %d bytes", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open health baseline: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) || openedInfo.Size() != linkInfo.Size() {
		return nil, 0, fmt.Errorf("health baseline changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read health baseline: %w", err)
	}
	if int64(len(payload)) > limit {
		return nil, 0, fmt.Errorf("health baseline exceeds %d bytes", limit)
	}
	if int64(len(payload)) != openedInfo.Size() {
		return nil, 0, fmt.Errorf("health baseline changed while reading")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var baseline healthmodel.Baseline
	if err := decoder.Decode(&baseline); err != nil {
		return nil, 0, fmt.Errorf("decode health baseline: invalid document")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, 0, fmt.Errorf("decode health baseline: document must contain exactly one JSON value")
	}
	if baseline.SchemaVersion != healthmodel.BaselineSchemaVersion || baseline.Timestamp.IsZero() || baseline.ClusterUUID == "" {
		return nil, 0, fmt.Errorf("decode health baseline: required metadata is missing or unsupported")
	}
	return &baseline, int64(len(payload)), nil
}

func SaveBaseline(path string, baseline healthmodel.Baseline, overwrite bool) (err error) {
	if path == "" {
		return fmt.Errorf("save health baseline: path is required")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".garga-health-baseline-*")
	if err != nil {
		return fmt.Errorf("save health baseline: create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("save health baseline: secure temporary file: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	if err = encoder.Encode(baseline); err != nil {
		return fmt.Errorf("save health baseline: encode document: %w", err)
	}
	if err = temporary.Sync(); err != nil {
		return fmt.Errorf("save health baseline: sync document: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return fmt.Errorf("save health baseline: close document: %w", err)
	}
	if err = activateBaseline(temporaryPath, path, overwrite); err != nil {
		return fmt.Errorf("save health baseline: activate document: %w", err)
	}
	return nil
}

func activateBaseline(temporaryPath, destination string, overwrite bool) error {
	if !overwrite {
		// A hard link publishes the fully synced inode only when the destination
		// does not exist, removing the stat/rename race that could replace a file.
		if err := os.Link(temporaryPath, destination); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("destination already exists")
			}
			return err
		}
		return os.Remove(temporaryPath)
	}
	if err := os.Rename(temporaryPath, destination); err == nil {
		return nil
	} else if _, statErr := os.Stat(destination); statErr != nil {
		return err
	}

	// Windows does not replace an existing destination with os.Rename. Move
	// the previous baseline aside and restore it if activation fails.
	backupFile, err := os.CreateTemp(filepath.Dir(destination), ".garga-health-baseline-backup-*")
	if err != nil {
		return err
	}
	backupPath := backupFile.Name()
	if closeErr := backupFile.Close(); closeErr != nil {
		_ = os.Remove(backupPath)
		return closeErr
	}
	if err := os.Remove(backupPath); err != nil {
		return err
	}
	if err := os.Rename(destination, backupPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		if restoreErr := os.Rename(backupPath, destination); restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore previous baseline: %w", restoreErr))
		}
		return err
	}
	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("remove previous baseline: %w", err)
	}
	return nil
}
