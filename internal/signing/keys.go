package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"runtime"
)

const MaxKeyFileBytes = 64 << 10

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	contents, err := readKeyFile(path, true)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(contents)
}

func ParsePrivateKey(contents []byte) (ed25519.PrivateKey, error) {
	trimmed := bytes.TrimSpace(contents)
	if block, rest := pem.Decode(trimmed); block != nil {
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("parse signing key: unexpected data after PEM block")
		}
		value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse signing key: invalid PKCS#8 key")
		}
		key, ok := value.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("parse signing key: key is not Ed25519")
		}
		return append(ed25519.PrivateKey(nil), key...), nil
	}
	decoded, err := decodeTextKey(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: expected PKCS#8 PEM, hex, or base64")
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		key := ed25519.PrivateKey(append([]byte(nil), decoded...))
		derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
		if !bytes.Equal(derived[ed25519.SeedSize:], key[ed25519.SeedSize:]) {
			return nil, fmt.Errorf("parse signing key: private key is inconsistent")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("parse signing key: invalid Ed25519 key length")
	}
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	contents, err := readKeyFile(path, false)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(contents)
}

func ParsePublicKey(contents []byte) (ed25519.PublicKey, error) {
	trimmed := bytes.TrimSpace(contents)
	if block, rest := pem.Decode(trimmed); block != nil {
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("parse public key: unexpected data after PEM block")
		}
		value, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: invalid PKIX key")
		}
		key, ok := value.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("parse public key: key is not Ed25519")
		}
		return append(ed25519.PublicKey(nil), key...), nil
	}
	decoded, err := decodeTextKey(trimmed)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("parse public key: expected PKIX PEM, 32-byte hex, or base64")
	}
	return ed25519.PublicKey(append([]byte(nil), decoded...)), nil
}

func KeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:16])
}

func readKeyFile(path string, private bool) ([]byte, error) {
	label := "public key"
	if private {
		label = "signing key"
	}
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("read %s: key must be a regular non-symlink file", label)
	}
	if linkInfo.Size() > MaxKeyFileBytes {
		return nil, fmt.Errorf("read %s: key file exceeds %d bytes", label, MaxKeyFileBytes)
	}
	if private && runtime.GOOS != "windows" && linkInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("read signing key: permissions must not grant group or other access")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(linkInfo, openedInfo) {
		return nil, fmt.Errorf("read %s: key changed while opening", label)
	}
	contents, err := io.ReadAll(io.LimitReader(file, MaxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if len(contents) > MaxKeyFileBytes || int64(len(contents)) != openedInfo.Size() {
		return nil, fmt.Errorf("read %s: key changed while reading", label)
	}
	return contents, nil
}

func decodeTextKey(value []byte) ([]byte, error) {
	if decoded, err := hex.DecodeString(string(value)); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(string(value))
}
