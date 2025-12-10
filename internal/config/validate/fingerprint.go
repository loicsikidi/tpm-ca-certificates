package validate

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/fingerprint"
)

// normalizeFingerprint removes colons and converts to uppercase for comparison.
func normalizeFingerprint(fp string) string {
	return strings.ToUpper(strings.ReplaceAll(fp, ":", ""))
}

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
	expectedFP, hashAlg := fp.GetFingerprintValue()
	actualFP := fingerprint.New(cert.Raw, hashAlg)

	if normalizeFingerprint(expectedFP) != normalizeFingerprint(actualFP) {
		return fmt.Errorf("fingerprint mismatch: expected %s, got %s", expectedFP, actualFP)
	}

	return nil
}

// ValidateFingerprintWithAlgorithm validates a certificate against an expected fingerprint using a specified algorithm.
func ValidateFingerprintWithAlgorithm(cert *x509.Certificate, expectedFP string, algorithm string) error {
	actualFP := fingerprint.New(cert.Raw, algorithm)

	if normalizeFingerprint(expectedFP) != normalizeFingerprint(actualFP) {
		return fmt.Errorf("fingerprint mismatch: expected %s, got %s", expectedFP, actualFP)
	}

	return nil
}
