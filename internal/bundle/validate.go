package bundle

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config/vendors"
	"github.com/loicsikidi/tpm-ca-certificates/internal/fingerprint"
)

// ValidationError represents a single validation error with its line number.
type ValidationError struct {
	Line    int
	Message string
}

// BundleValidator handles bundle validation operations.
type BundleValidator struct {
	errors    []ValidationError
	maxErrors int
}

// NewBundleValidator creates a new bundle validator.
func NewBundleValidator() *BundleValidator {
	return &BundleValidator{
		errors:    make([]ValidationError, 0),
		maxErrors: 10,
	}
}

// ValidateBundle validates a TPM trust bundle from bytes.
//
// It performs comprehensive validation including:
//   - Global metadata block format and required fields
//   - Certificate metadata format and required fields
//   - PEM block validity
//   - Metadata consistency with certificate content
//   - Vendor ID validity
//
// Returns the list of validation errors (max 10).
//
// Example:
//
//	validator := bundle.NewBundleValidator()
//	errors, err := validator.ValidateBundle(bundleData)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if len(errors) > 0 {
//	    for _, err := range errors {
//	        fmt.Printf("Line %d: %s\n", err.Line, err.Message)
//	    }
//	}
func (v *BundleValidator) ValidateBundle(data []byte) ([]ValidationError, error) {
	return v.ValidateBundleFromReader(bytes.NewReader(data))
}

// ValidateBundleFromReader validates a TPM trust bundle from an [io.Reader].
func (v *BundleValidator) ValidateBundleFromReader(reader io.Reader) ([]ValidationError, error) {
	scanner := bufio.NewScanner(reader)
	lineNum := 0

	// Track validation state
	var (
		inGlobalMetadata bool
		foundDate        bool
		foundCommit      bool
		inCertMetadata   bool
		certMetadata     *certificateMetadata
		certStartLine    int
		pemBlock         strings.Builder
		inPEMBlock       bool
		pemStartLine     int
	)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Validate global metadata block
		if lineNum == 1 {
			if line != GlobalMetadataPrefix {
				v.addError(lineNum, "bundle must start with global metadata block marker '"+GlobalMetadataPrefix+"'")
			}
			inGlobalMetadata = true
			continue
		}

		// Process global metadata
		if inGlobalMetadata {
			if !strings.HasPrefix(line, GlobalMetadataPrefix) {
				// End of global metadata
				inGlobalMetadata = false
				if !foundDate {
					v.addError(lineNum, fmt.Sprintf("global metadata missing required '%q' field", MetadataKeyDate.Key()))
				}
				if !foundCommit {
					v.addError(lineNum, fmt.Sprintf("global metadata missing required '%q' field", MetadataKeyCommit.Key()))
				}
			} else {
				// Parse global metadata fields
				if strings.HasPrefix(line, MetadataKeyDate.String()) {
					foundDate = true
					dateValue := strings.TrimSpace(strings.TrimPrefix(line, MetadataKeyDate.String()))
					if err := ValidateDate(dateValue); err != nil {
						v.addError(lineNum, fmt.Sprintf("invalid date format: %v", err))
					}
				}
				if strings.HasPrefix(line, MetadataKeyCommit.String()) {
					foundCommit = true
					commitValue := strings.TrimSpace(strings.TrimPrefix(line, MetadataKeyCommit.String()))
					if err := ValidateCommit(commitValue); err != nil {
						v.addError(lineNum, fmt.Sprintf("invalid commit hash: %v", err))
					}
				}
			}
			continue
		}

		// Skip empty lines outside of metadata/PEM blocks
		if line == "" && !inPEMBlock {
			continue
		}

		if line == CertMetadataPrefix && !inCertMetadata && !inPEMBlock {
			inCertMetadata = true
			certMetadata = &certificateMetadata{
				startLine: lineNum,
			}
			certStartLine = lineNum
			continue
		}

		// Process certificate metadata
		if inCertMetadata && strings.HasPrefix(line, CertMetadataPrefix) {
			if line == CertMetadataPrefix {
				// Empty metadata line (separator before Owner)
				continue
			}

			field := strings.TrimPrefix(line, CertMetadataPrefix+" ")

			// Handle special case for "Not Valid After :" with space before colon
			// This matches the format in the spec where "Not Valid After :" has alignment
			var key, value string
			if strings.Contains(field, " : ") {
				parts := strings.SplitN(field, " : ", 2)
				if len(parts) == 2 {
					key = strings.TrimSpace(parts[0])
					value = parts[1]
				}
				if key != CertMetadataKeyNotValidAfter.Key() {
					v.addError(lineNum, fmt.Sprintf("invalid metadata format: unexpected space before colon in %q", field))
					continue
				}
			} else {
				parts := strings.SplitN(field, ": ", 2)
				if len(parts) != 2 {
					v.addError(lineNum, fmt.Sprintf("invalid metadata format: expected 'Key: Value', got %q", field))
					continue
				}
				key = parts[0]
				value = parts[1]
			}

			switch key {
			case CertMetadataKeyCertificate.Key():
				certMetadata.certificate = value
			case CertMetadataKeyOwner.Key():
				certMetadata.owner = value
				if err := v.validateVendorID(value); err != nil {
					v.addError(lineNum, fmt.Sprintf("invalid vendor ID: %v", err))
				}
			case CertMetadataKeyIssuer.Key():
				certMetadata.issuer = value
			case CertMetadataKeySerialNumber.Key():
				certMetadata.serialNumber = value
			case CertMetadataKeySubject.Key():
				certMetadata.subject = value
			case CertMetadataKeyNotValidBefore.Key():
				certMetadata.notBefore = value
			case CertMetadataKeyNotValidAfter.Key():
				certMetadata.notAfter = value
			case CertMetadataKeyFingerprintSHA256.Key():
				certMetadata.sha256 = value
				if err := v.validateFingerprintFormat(value, 32); err != nil {
					v.addError(lineNum, fmt.Sprintf("invalid SHA-256 fingerprint: %v", err))
				}
			case CertMetadataKeyFingerprintSHA1.Key():
				certMetadata.sha1 = value
				if err := v.validateFingerprintFormat(value, 20); err != nil {
					v.addError(lineNum, fmt.Sprintf("invalid SHA1 fingerprint: %v", err))
				}
			}
			continue
		}

		// Start of PEM block
		if strings.HasPrefix(line, PEMBeginMarker) {
			if certMetadata == nil {
				v.addError(lineNum, "certificate found without metadata block")
				continue
			}

			inCertMetadata = false
			inPEMBlock = true
			pemStartLine = lineNum
			pemBlock.Reset()
			pemBlock.WriteString(line)
			pemBlock.WriteString("\n")

			v.validateCertificateMetadata(certMetadata, certStartLine)
			continue
		}

		// Process PEM block
		if inPEMBlock {
			pemBlock.WriteString(line)
			pemBlock.WriteString("\n")

			if strings.HasPrefix(line, PEMEndMarker) {
				inPEMBlock = false

				block, _ := pem.Decode([]byte(pemBlock.String()))
				if block == nil {
					v.addError(pemStartLine, "failed to decode PEM block")
					certMetadata = nil
					continue
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					v.addError(pemStartLine, fmt.Sprintf("failed to parse certificate: %v", err))
					certMetadata = nil
					continue
				}

				v.validateMetadataConsistency(cert, certMetadata, certStartLine)

				// Reset for next certificate
				certMetadata = nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read bundle: %w", err)
	}

	// Check if we reached end of file while still in global metadata
	if inGlobalMetadata {
		if !foundDate {
			v.addError(lineNum, "global metadata missing required 'Date' field")
		}
		if !foundCommit {
			v.addError(lineNum, "global metadata missing required 'Commit' field")
		}
	}

	return v.errors, nil
}

// certificateMetadata holds parsed certificate metadata for validation.
type certificateMetadata struct {
	startLine    int
	certificate  string
	owner        string
	issuer       string
	serialNumber string
	subject      string
	notBefore    string
	notAfter     string
	sha256       string
	sha1         string
}

// addError adds a validation error if the limit hasn't been reached.
func (v *BundleValidator) addError(line int, message string) {
	if len(v.errors) >= v.maxErrors {
		return
	}

	v.errors = append(v.errors, ValidationError{
		Line:    line,
		Message: message,
	})
}

// validateVendorID validates that a vendor ID is valid according to TCG registry.
func (v *BundleValidator) validateVendorID(id string) error {
	vendorID := vendors.ID(id)
	return vendorID.Validate()
}

// validateFingerprintFormat validates the fingerprint format (uppercase with colons).
func (v *BundleValidator) validateFingerprintFormat(fp string, expectedBytes int) error {
	parts := strings.Split(fp, ":")
	if len(parts) != expectedBytes {
		return fmt.Errorf("expected %d colon-separated parts, got %d", expectedBytes, len(parts))
	}

	if !fingerprint.IsValid(fp) {
		return fmt.Errorf("expected uppercase hexadecimal with colon separators")
	}

	return nil
}

// validateCertificateMetadata validates that all required metadata fields are present.
func (v *BundleValidator) validateCertificateMetadata(meta *certificateMetadata, startLine int) {
	if meta.certificate == "" {
		v.addError(startLine, "certificate metadata missing required '"+CertMetadataKeyCertificate.Key()+"' field")
	}
	if meta.owner == "" {
		v.addError(startLine, "certificate metadata missing required '"+CertMetadataKeyOwner.Key()+"' field")
	}
	if meta.issuer == "" {
		v.addError(startLine, "certificate metadata missing required '"+CertMetadataKeyIssuer.Key()+"' field")
	}
	if meta.serialNumber == "" {
		v.addError(startLine, "certificate metadata missing required '"+CertMetadataKeySerialNumber.Key()+"' field")
	}
	if meta.subject == "" {
		v.addError(startLine, "certificate metadata missing required '"+CertMetadataKeySubject.Key()+"' field")
	}
	if meta.notBefore == "" {
		v.addError(startLine, "certificate metadata missing required '"+CertMetadataKeyNotValidBefore.Key()+"' field")
	}
	if meta.notAfter == "" {
		v.addError(startLine, "certificate metadata missing required '"+CertMetadataKeyNotValidAfter.Key()+"' field")
	}
	if meta.sha256 == "" {
		v.addError(startLine, "certificate metadata missing required '"+CertMetadataKeyFingerprintSHA256.Key()+"' field")
	}
	if meta.sha1 == "" {
		v.addError(startLine, "certificate metadata missing required '"+CertMetadataKeyFingerprintSHA1.Key()+"' field")
	}
}

// validateMetadataConsistency validates that metadata matches the actual certificate.
func (v *BundleValidator) validateMetadataConsistency(cert *x509.Certificate, meta *certificateMetadata, startLine int) {
	// Validate subject
	expectedSubject := cert.Subject.String()
	if meta.subject != expectedSubject {
		v.addError(startLine, fmt.Sprintf("subject mismatch: metadata has %q, certificate has %q", meta.subject, expectedSubject))
	}

	// Validate issuer
	expectedIssuer := cert.Issuer.String()
	if meta.issuer != expectedIssuer {
		v.addError(startLine, fmt.Sprintf("issuer mismatch: metadata has %q, certificate has %q", meta.issuer, expectedIssuer))
	}

	// Validate SHA-256 fingerprint
	if meta.sha256 != "" {
		actualSHA256 := sha256.Sum256(cert.Raw)
		expectedSHA256 := formatFingerprint(actualSHA256[:])
		if meta.sha256 != expectedSHA256 {
			v.addError(startLine, fmt.Sprintf("SHA-256 fingerprint mismatch: metadata has %q, certificate has %q", meta.sha256, expectedSHA256))
		}
	}

	// Validate SHA1 fingerprint
	if meta.sha1 != "" {
		actualSHA1 := sha1.Sum(cert.Raw)
		expectedSHA1 := formatFingerprint(actualSHA1[:])
		if meta.sha1 != expectedSHA1 {
			v.addError(startLine, fmt.Sprintf("SHA1 fingerprint mismatch: metadata has %q, certificate has %q", meta.sha1, expectedSHA1))
		}
	}

	// Validate NotBefore timestamp
	// Use custom format with zero-padded day (ANSIC uses space-padded day)
	expectedNotBefore := cert.NotBefore.Format("Mon Jan 02 15:04:05 2006")
	if meta.notBefore != expectedNotBefore {
		v.addError(startLine, fmt.Sprintf("not valid before mismatch: metadata has %q, certificate has %q", meta.notBefore, expectedNotBefore))
	}

	// Validate NotAfter timestamp
	// Use custom format with zero-padded day (ANSIC uses space-padded day)
	expectedNotAfter := cert.NotAfter.Format("Mon Jan 02 15:04:05 2006")
	if meta.notAfter != expectedNotAfter {
		v.addError(startLine, fmt.Sprintf("not valid after mismatch: metadata has %q, certificate has %q", meta.notAfter, expectedNotAfter))
	}

	// Validate serial number format
	// The metadata format is "decimal (0xhex)"
	expectedSerial := fmt.Sprintf("%d (0x%x)", cert.SerialNumber, cert.SerialNumber)
	if meta.serialNumber != expectedSerial {
		v.addError(startLine, fmt.Sprintf("serial number mismatch: metadata has %q, certificate has %q", meta.serialNumber, expectedSerial))
	}
}

// ValidateDate validates that a date is in YYYY-MM-DD format.
//
// It checks both the format pattern and that the date is actually valid
// (e.g., not 2024-13-45).
//
// Example:
//
//	err := bundle.ValidateDate("2024-12-08")
//	if err != nil {
//	    log.Fatal(err)
//	}
func ValidateDate(date string) error {
	matched, err := regexp.MatchString(`^\d{4}-\d{2}-\d{2}$`, date)
	if err != nil {
		return err
	}
	if !matched {
		return fmt.Errorf("date must be in YYYY-MM-DD format, got: %s", date)
	}

	// Parse to ensure it's a valid date
	_, err = time.Parse("2006-01-02", date)
	if err != nil {
		return fmt.Errorf("invalid date: %w", err)
	}

	return nil
}

// ValidateCommit validates that a commit hash is a valid 40-character
// lowercase hexadecimal string.
//
// Example:
//
//	err := bundle.ValidateCommit("a1b2c3d4e5f67890123456789abcdef012345678")
//	if err != nil {
//	    log.Fatal(err)
//	}
func ValidateCommit(commit string) error {
	if len(commit) != 40 {
		return fmt.Errorf("commit must be a 40-character hex string, got %d characters: %s", len(commit), commit)
	}

	matched, err := regexp.MatchString(`^[0-9a-f]{40}$`, commit)
	if err != nil {
		return err
	}
	if !matched {
		return fmt.Errorf("commit must be a 40-character hex string, got: %s", commit)
	}

	return nil
}
