package report

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReportPackageDoesNotImportOrchestrationLayers(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(file)
	forbidden := []string{
		"github.com/cumakurt/garga/internal/scanner",
		"github.com/cumakurt/garga/internal/cli",
		"github.com/cumakurt/garga/internal/fingerprint",
		"github.com/cumakurt/garga/internal/capability",
		"github.com/cumakurt/garga/internal/probe",
		"github.com/cumakurt/garga/internal/credential",
		"github.com/cumakurt/garga/internal/checks",
		"github.com/cumakurt/garga/internal/vulnerability",
		"github.com/cumakurt/garga/internal/transport",
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
		t.Fatalf("walk report package: %v", err)
	}
}
