package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func GenerateTestCert(t *testing.T) (*x509.Certificate, string) {
	t.Helper()
	der, fingerprint := generateTestCertWithExpiry(t, time.Now().Add(365*24*time.Hour))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, fingerprint
}

func GenerateTestCertDER(t *testing.T) ([]byte, string) {
	t.Helper()
	return generateTestCertWithExpiry(t, time.Now().Add(365*24*time.Hour))
}

// GenerateTestCertExpiringSoon generates a test certificate that expires in the specified number of days.
func GenerateTestCertExpiringSoon(t *testing.T, daysUntilExpiry int) ([]byte, string) {
	t.Helper()
	expiryDate := time.Now().Add(time.Duration(daysUntilExpiry) * 24 * time.Hour)
	return generateTestCertWithExpiry(t, expiryDate)
}

// GenerateTestCertExpired generates a test certificate that has already expired.
func GenerateTestCertExpired(t *testing.T) ([]byte, string) {
	t.Helper()
	expiryDate := time.Now().Add(-10 * 24 * time.Hour)
	return generateTestCertWithExpiry(t, expiryDate)
}

func generateTestCertWithExpiry(t *testing.T, notAfter time.Time) ([]byte, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	h := sha1.Sum(certDER)
	fingerprint := hex.EncodeToString(h[:])

	return certDER, fingerprint
}

// ParseCertificate parses a PEM-encoded certificate and returns an [x509.Certificate].
func ParseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
