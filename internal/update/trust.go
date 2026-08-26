package update

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// defaultPublicKeyHex is the pre-release Ed25519 trust root. The matching private
// key is held by maintainers and is not stored in this repository.
const defaultPublicKeyHex = "58c09b78f3d2bff204284d3dccf655f6857dd7e9ea46b2efe9a7f9e23d9d45fd"

// DefaultPublicKey returns the embedded signature trust root.
func DefaultPublicKey() ed25519.PublicKey {
	key, err := hex.DecodeString(defaultPublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		panic("update: embedded trust root is invalid")
	}
	return ed25519.PublicKey(key)
}

func publicKeyOrDefault(key ed25519.PublicKey) (ed25519.PublicKey, error) {
	if len(key) == 0 {
		return DefaultPublicKey(), nil
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: trust root is invalid", ErrVerification)
	}
	return key, nil
}
