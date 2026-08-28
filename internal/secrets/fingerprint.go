package secrets

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func newDedupKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate secrets dedup key: %w", err)
	}
	return key, nil
}

func fingerprintSecret(key []byte, category, value string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(category))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
