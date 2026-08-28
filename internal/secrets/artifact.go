package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteReportFile atomically replaces one owner-readable report artifact.
func WriteReportFile(path string, format Format, result ScanReport) (err error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("write secrets report file: path is required")
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("write secrets report file: refusing to replace a symbolic link")
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("inspect secrets report file: %w", statErr)
	}

	directory := filepath.Dir(path)
	base := filepath.Base(path)
	temporary, err := os.CreateTemp(directory, "."+base+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary secrets report file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if err != nil {
			_ = os.Remove(temporaryPath)
		}
	}()

	if err = temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary secrets report file: %w", err)
	}
	if err = WriteReport(temporary, format, result); err != nil {
		return err
	}
	if err = temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary secrets report file: %w", err)
	}
	if err = temporary.Close(); err != nil {
		return fmt.Errorf("close temporary secrets report file: %w", err)
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate secrets report file: %w", err)
	}
	return nil
}
