package validate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
)

func generateTestCert(t *testing.T) *x509.Certificate {
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
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func TestValidateFingerprint(t *testing.T) {
	cert := generateTestCert(t)

	sha1Actual := hex.EncodeToString(computeSHA1(cert.Raw))
	sha256Actual := hex.EncodeToString(computeSHA256(cert.Raw))

	tests := []struct {
		name        string
		fingerprint config.Fingerprint
		wantError   bool
	}{
		{
			name: "valid SHA1 with colons",
			fingerprint: config.Fingerprint{
				SHA1: formatWithColons(sha1Actual),
			},
			wantError: false,
		},
		{
			name: "valid SHA1 without colons",
			fingerprint: config.Fingerprint{
				SHA1: sha1Actual,
			},
			wantError: false,
		},
		{
			name: "valid SHA256",
			fingerprint: config.Fingerprint{
				SHA256: formatWithColons(sha256Actual),
			},
			wantError: false,
		},
		{
			name: "invalid SHA1",
			fingerprint: config.Fingerprint{
				SHA1: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
			},
			wantError: true,
		},
		{
			name: "invalid SHA256",
			fingerprint: config.Fingerprint{
				SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
			},
			wantError: true,
		},
		{
			name:        "no fingerprints provided",
			fingerprint: config.Fingerprint{},
			wantError:   true,
		},
		{
			name: "malformed fingerprint",
			fingerprint: config.Fingerprint{
				SHA1: "not-a-hex-string",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFingerprint(cert, tt.fingerprint)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateFingerprint() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestParseFingerprint(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "with colons",
			input:   "AA:BB:CC:DD",
			want:    "aabbccdd",
			wantErr: false,
		},
		{
			name:    "without colons",
			input:   "AABBCCDD",
			want:    "aabbccdd",
			wantErr: false,
		},
		{
			name:    "with spaces",
			input:   "AA BB CC DD",
			want:    "aabbccdd",
			wantErr: false,
		},
		{
			name:    "invalid hex",
			input:   "GGHHII",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFingerprint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && hex.EncodeToString(got) != tt.want {
				t.Errorf("parseFingerprint() = %v, want %v", hex.EncodeToString(got), tt.want)
			}
		})
	}
}

func formatWithColons(hexStr string) string {
	var result string
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			result += ":"
		}
		result += hexStr[i : i+2]
	}
	return result
}

func computeSHA1(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

func computeSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
