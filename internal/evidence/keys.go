package evidence

import (
	"crypto/ed25519"

	"github.com/cumakurt/garga/internal/signing"
)

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	return signing.LoadPrivateKey(path)
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	return signing.LoadPublicKey(path)
}

func keyID(publicKey ed25519.PublicKey) string {
	return signing.KeyID(publicKey)
}
