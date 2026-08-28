package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLoadKeysRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.key")
	publicPath := filepath.Join(directory, "public.key")
	if err := os.WriteFile(privatePath, []byte(hex.EncodeToString(privateKey)), 0o600); err != nil {
		t.Fatalf("WriteFile(private) error = %v", err)
	}
	if err := os.WriteFile(publicPath, []byte(hex.EncodeToString(publicKey)), 0o600); err != nil {
		t.Fatalf("WriteFile(public) error = %v", err)
	}
	privateLink := filepath.Join(directory, "private-link.key")
	publicLink := filepath.Join(directory, "public-link.key")
	if err := os.Symlink(privatePath, privateLink); err != nil {
		t.Fatalf("Symlink(private) error = %v", err)
	}
	if err := os.Symlink(publicPath, publicLink); err != nil {
		t.Fatalf("Symlink(public) error = %v", err)
	}
	if _, err := LoadPrivateKey(privateLink); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("LoadPrivateKey(symlink) error = %v", err)
	}
	if _, err := LoadPublicKey(publicLink); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("LoadPublicKey(symlink) error = %v", err)
	}
}

func TestParsePrivateKeyRejectsInconsistentExpandedKey(t *testing.T) {
	t.Parallel()

	value := make([]byte, ed25519.PrivateKeySize)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	if _, err := ParsePrivateKey([]byte(hex.EncodeToString(value))); err == nil || !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("ParsePrivateKey(inconsistent) error = %v", err)
	}
}
