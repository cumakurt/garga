package secrets

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSecretsEngineIsNotImportedByScanPath(t *testing.T) {
	t.Parallel()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	forbidden := []string{
		"internal/app",
		"internal/scanner",
		"internal/fingerprint",
		"internal/capability",
		"internal/checks",
		"internal/probe",
		"internal/health",
		"internal/report",
		"internal/credential/audit",
		"internal/credential/detect",
	}
	importPath := "github.com/cumakurt/garga/internal/secrets"
	for _, relative := range forbidden {
		assertDirDoesNotImport(t, filepath.Join(root, relative), importPath)
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
				t.Errorf("%s imports %s", path, spec.Path.Value)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}
