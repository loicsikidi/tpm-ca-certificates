package validate

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
)

// ValidateFingerprint validates a certificate against the most secure fingerprint available.
//
// It uses the most secure hash algorithm available from the fingerprint configuration.
// Priority order: SHA512 > SHA384 > SHA256.
// The fingerprint strings can be in the format "AA:BB:CC:DD" or "AABBCCDD".
//
// Example:
//
//	cert, _ := x509.ParseCertificate(certBytes)
//	fp := config.Fingerprint{SHA256: "AA:BB:CC:..."}
//	err := validate.ValidateFingerprint(cert, fp)
//	if err != nil {
//	    log.Fatal("Certificate validation failed:", err)
//	}
func ValidateFingerprint(cert *x509.Certificate, fp config.Fingerprint) error {
	expectedFP, hashFunc := fp.GetFingerprintValue()

	expected, err := parseFingerprint(expectedFP)
	if err != nil {
		return fmt.Errorf("invalid fingerprint format: %w", err)
	}

	hashFunc.Write(cert.Raw)
	actual := hashFunc.Sum(nil)

	if !bytesEqual(actual, expected) {
		return fmt.Errorf("fingerprint mismatch: expected %s, got %s",
			formatFingerprint(expected), formatFingerprint(actual))
	}

	return nil
}

// parseFingerprint converts a fingerprint string to bytes.
// Accepts both "AA:BB:CC:DD" and "AABBCCDD" formats.
func parseFingerprint(fp string) ([]byte, error) {
	cleaned := strings.ReplaceAll(fp, ":", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ToLower(cleaned)

	decoded, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}

	return decoded, nil
}

// formatFingerprint formats bytes as a colon-separated hex string.
func formatFingerprint(data []byte) string {
	hex := fmt.Sprintf("%X", data)
	var result strings.Builder
	for i := 0; i < len(hex); i += 2 {
		if i > 0 {
			result.WriteString(":")
		}
		result.WriteString(hex[i : i+2])
	}
	return result.String()
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
