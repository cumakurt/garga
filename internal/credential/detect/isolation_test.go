package detect

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDetectEngineIsNotImportedByScanPath(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	forbidden := []string{
		"internal/app",
		"internal/scanner",
		"internal/fingerprint",
		"internal/capability",
		"internal/checks",
		"internal/probe",
		"internal/health",
		"internal/report",
	}
	detectImport := "github.com/cumakurt/garga/internal/credential/detect"
	for _, relative := range forbidden {
		assertDirDoesNotImport(t, filepath.Join(root, relative), detectImport)
	}
}

func assertDirDoesNotImport(t *testing.T, dir, importPath string) {
	t.Helper()
	fileSet := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		parsed, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range parsed.Imports {
			if strings.Trim(spec.Path.Value, `"`) == importPath {
				t.Errorf("%s imports %s", path, importPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}
