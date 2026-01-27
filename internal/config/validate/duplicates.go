package validate

import (
	"crypto/x509"
	"fmt"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
)

// DuplicateError represents a duplicate certificate error.
type DuplicateError struct {
	Type         string // "uri" or "fingerprint"
	ExistingName string // Name of the existing certificate (only for fingerprint duplicates)
}

func (e *DuplicateError) Error() string {
	if e.Type == "uri" {
		return "certificate already exists (duplicate URI)"
	}
	return fmt.Sprintf("certificate already exists (duplicate fingerprint, matches '%s')", e.ExistingName)
}

// ContainsCertificate checks if a certificate already exists in the list
func ContainsCertificate(certs []config.Certificate, cert config.Certificate) bool {
	for _, c := range certs {
		if c.Equal(&cert) {
			return true
		}
	}
	return false
}

// CheckCertificate checks if a certificate already exists in the list.
//
// It checks for duplicates by:
//   - Source location (URI or URL): exact match
//   - Fingerprint: compares fingerprints across all hash algorithms
//
// Returns a [DuplicateError] if a duplicate is found, nil otherwise.
func CheckCertificate(certs []config.Certificate, uri string, cert *x509.Certificate) error {
	if err := checkCertificateURI(certs, uri); err != nil {
		return err
	}
	return checkCertificateFingerprint(certs, cert)
}

func checkCertificateURI(certs []config.Certificate, uri string) error {
	for _, cert := range certs {
		if cert.GetSourceLocation() == uri {
			return &DuplicateError{Type: "uri"}
		}
	}
	return nil
}

func checkCertificateFingerprint(certs []config.Certificate, x509Cert *x509.Certificate) error {
	for _, cert := range certs {
		// ValidateFingerprint returns nil if the fingerprints match
		if err := ValidateFingerprint(x509Cert, cert.Validation.Fingerprint); err == nil {
			return &DuplicateError{Type: "fingerprint", ExistingName: cert.Name}
		}
	}
	return nil
}
