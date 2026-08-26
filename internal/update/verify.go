package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// VerifyManifest checks an Ed25519 signature over the exact manifest bytes.
func VerifyManifest(publicKey ed25519.PublicKey, manifest, signature []byte) error {
	key, err := publicKeyOrDefault(publicKey)
	if err != nil {
		return err
	}
	if len(manifest) == 0 || len(manifest) > maxManifestBytes {
		return fmt.Errorf("%w: manifest size is invalid", ErrVerification)
	}
	if len(signature) == 0 || len(signature) > maxDetachedSignatureBytes {
		return fmt.Errorf("%w: detached signature size is invalid", ErrVerification)
	}
	decoded, err := hex.DecodeString(string(bytes.TrimSpace(signature)))
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return fmt.Errorf("%w: detached signature is invalid", ErrVerification)
	}
	if !ed25519.Verify(key, manifest, decoded) {
		return fmt.Errorf("%w: manifest signature does not match the trust root", ErrVerification)
	}
	return nil
}
