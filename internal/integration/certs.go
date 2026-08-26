package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type tlsMaterial struct {
	Dir     string
	RootCAs *x509.CertPool
}

func generateTLSMaterial() (tlsMaterial, error) {
	dir, err := os.MkdirTemp("", "garga-es-certs-")
	if err != nil {
		return tlsMaterial{}, err
	}
	material, err := writeTLSMaterial(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return tlsMaterial{}, err
	}
	return material, nil
}

func writeTLSMaterial(dir string) (tlsMaterial, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tlsMaterial{}, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "garga-integration-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return tlsMaterial{}, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tlsMaterial{}, err
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tlsMaterial{}, err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return tlsMaterial{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return tlsMaterial{}, err
	}
	files := []struct {
		name      string
		blockType string
		der       []byte
		perm      os.FileMode
	}{
		{"ca.crt", "CERTIFICATE", caDER, 0644},
		{"http.crt", "CERTIFICATE", serverDER, 0644},
		{"http.key", "PRIVATE KEY", keyDER, 0600},
	}
	for _, file := range files {
		if writeErr := writePEM(filepath.Join(dir, file.name), file.blockType, file.der, file.perm); writeErr != nil {
			return tlsMaterial{}, writeErr
		}
	}
	if err := os.Chmod(dir, 0755); err != nil {
		return tlsMaterial{}, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return tlsMaterial{Dir: dir, RootCAs: pool}, nil
}

func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, &pem.Block{Type: blockType, Bytes: der})
}

func redactDiagnostics(text string, secrets []string) string {
	redacted := text
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		redacted = strings.ReplaceAll(redacted, secret, "[redacted]")
	}
	return redacted
}
