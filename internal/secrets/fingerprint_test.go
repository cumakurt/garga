package secrets

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFingerprintIsStableAndDoesNotEmbedSecret(t *testing.T) {
	t.Parallel()
	key := []byte("garga-test-dedup-key-not-a-secret")
	secret := "fake-password-garga-test-ONLY"
	first := fingerprintSecret(key, "credential.password", secret)
	second := fingerprintSecret(key, "credential.password", secret)
	if first != second || first == "" {
		t.Fatalf("fingerprint not stable: %q %q", first, second)
	}
	if first == secret {
		t.Fatal("fingerprint equals plaintext secret")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("credential.password"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(secret))
	if first != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("fingerprint is not HMAC-SHA256")
	}
}

func TestShannonEntropyOfRepeatedCharsIsLow(t *testing.T) {
	t.Parallel()
	if shannonEntropy("aaaaaaaaaaaaaaaaaaaa") >= 1 {
		t.Fatal("repeated characters should have near-zero entropy")
	}
	if shannonEntropy("s9f8a7d6s5f4a3d2s1f0a9d8s7f6a5d4s3f2") < 3 {
		t.Fatal("mixed charset should have high entropy")
	}
}
