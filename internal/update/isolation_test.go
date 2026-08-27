package update

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUpdatePackageDoesNotImportOrchestrationLayers(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(file)
	forbidden := []string{
		"github.com/cumakurt/garga/internal/scanner",
		"github.com/cumakurt/garga/internal/cli",
		"github.com/cumakurt/garga/internal/app",
		"github.com/cumakurt/garga/internal/fingerprint",
		"github.com/cumakurt/garga/internal/capability",
		"github.com/cumakurt/garga/internal/probe",
		"github.com/cumakurt/garga/internal/credential",
		"github.com/cumakurt/garga/internal/checks",
		"github.com/cumakurt/garga/internal/report",
		"github.com/spf13/cobra",
	}
	fileSet := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		parsed, parseErr := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, spec := range parsed.Imports {
			importPath := strings.Trim(spec.Path.Value, `"`)
			for _, blocked := range forbidden {
				if importPath == blocked || strings.HasPrefix(importPath, blocked+"/") {
					t.Errorf("%s imports %s", path, importPath)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk update package: %v", err)
	}
}

func TestUpdatePackageIsNotImportedByScanPath(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	importPath := "github.com/cumakurt/garga/internal/update"
	forbidden := []string{
		"internal/app",
		"internal/scanner",
		"internal/fingerprint",
		"internal/capability",
		"internal/checks",
		"internal/probe",
		"internal/credential",
		"internal/report",
	}
	fileSet := token.NewFileSet()
	for _, relative := range forbidden {
		err := filepath.WalkDir(filepath.Join(root, relative), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			parsed, parseErr := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return parseErr
			}
			for _, spec := range parsed.Imports {
				if strings.Trim(spec.Path.Value, `"`) == importPath {
					t.Errorf("%s imports %s", path, importPath)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", relative, err)
		}
	}
}
