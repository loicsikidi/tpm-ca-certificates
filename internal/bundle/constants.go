package bundle

import (
	"fmt"

	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
)

// BundleType represents the type of TPM trust bundle.
type BundleType string

const (
	// TypeUnspecified indicates that the bundle type was not specified.
	// This is used as a sentinel value to trigger automatic detection.
	TypeUnspecified BundleType = ""

	// TypeRoot indicates a bundle containing root certificates.
	TypeRoot BundleType = "root"

	// TypeIntermediate indicates a bundle containing intermediate certificates.
	TypeIntermediate BundleType = "intermediate"
)

// String returns the string representation of the bundle type.
func (t BundleType) String() string {
	return string(t)
}

// Validate checks if the bundle type is valid.
func (t BundleType) Validate() error {
	switch t {
	case TypeUnspecified, TypeRoot, TypeIntermediate:
		return nil
	default:
		return fmt.Errorf("invalid bundle type %q: must be one of [root, intermediate]", t)
	}
}

// DefaultFilename returns the default output filename for the bundle type.
func (t BundleType) DefaultFilename() string {
	switch t {
	case TypeIntermediate:
		return cache.IntermediateBundleFilename
	case TypeRoot, TypeUnspecified:
		fallthrough
	default:
		return cache.RootBundleFilename
	}
}

// Description returns the human-readable description for the bundle type
// used in the bundle header.
func (t BundleType) Description() string {
	switch t {
	case TypeIntermediate:
		return "TPM Intermediate Endorsement Certificates"
	case TypeRoot, TypeUnspecified:
		fallthrough
	default:
		return "TPM Root Endorsement Certificates"
	}
}

// Metadata prefixes used in the bundle format.
const (
	// GlobalMetadataPrefix is the prefix for global metadata lines.
	GlobalMetadataPrefix = "##"

	// CertMetadataPrefix is the prefix for certificate metadata lines.
	CertMetadataPrefix = "#"

	// PEMBeginMarker is the PEM certificate start marker.
	PEMBeginMarker = "-----BEGIN CERTIFICATE-----"

	// PEMEndMarker is the PEM certificate end marker.
	PEMEndMarker = "-----END CERTIFICATE-----"
)

// MetadataKey represents a metadata key with its prefix.
type MetadataKey struct {
	prefix string
	key    string
}

// String returns the formatted metadata key as "Prefix Key: ".
//
// Example:
//
//	fmt.Println(MetadataKeyDate) // Output: "## Date: "
func (m MetadataKey) String() string {
	return m.prefix + " " + m.key + ": "
}

// Key returns the raw key name without prefix.
func (m MetadataKey) Key() string {
	return m.key
}

// Prefix returns the prefix used for this metadata key.
func (m MetadataKey) Prefix() string {
	return m.prefix
}

// Global metadata keys used in the bundle header.
var (
	// MetadataKeyDate is the key for the bundle generation date (YYYY-MM-DD format).
	MetadataKeyDate = MetadataKey{prefix: GlobalMetadataPrefix, key: "Date"}

	// MetadataKeyCommit is the key for the Git commit hash (40-character hex string).
	MetadataKeyCommit = MetadataKey{prefix: GlobalMetadataPrefix, key: "Commit"}
)

// Certificate metadata keys used in certificate blocks.
var (
	// CertMetadataKeyCertificate is the key for the certificate name/identifier.
	CertMetadataKeyCertificate = MetadataKey{prefix: CertMetadataPrefix, key: "Certificate"}

	// CertMetadataKeyOwner is the key for the certificate owner's Vendor ID.
	CertMetadataKeyOwner = MetadataKey{prefix: CertMetadataPrefix, key: "Owner"}

	// CertMetadataKeyIssuer is the key for the certificate issuer DN.
	CertMetadataKeyIssuer = MetadataKey{prefix: CertMetadataPrefix, key: "Issuer"}

	// CertMetadataKeySerialNumber is the key for the certificate serial number.
	CertMetadataKeySerialNumber = MetadataKey{prefix: CertMetadataPrefix, key: "Serial Number"}

	// CertMetadataKeySubject is the key for the certificate subject DN.
	CertMetadataKeySubject = MetadataKey{prefix: CertMetadataPrefix, key: "Subject"}

	// CertMetadataKeyNotValidBefore is the key for the certificate validity start date.
	CertMetadataKeyNotValidBefore = MetadataKey{prefix: CertMetadataPrefix, key: "Not Valid Before"}

	// CertMetadataKeyNotValidAfter is the key for the certificate validity end date.
	CertMetadataKeyNotValidAfter = MetadataKey{prefix: CertMetadataPrefix, key: "Not Valid After"}

	// CertMetadataKeyFingerprintSHA256 is the key for the SHA-256 fingerprint.
	CertMetadataKeyFingerprintSHA256 = MetadataKey{prefix: CertMetadataPrefix, key: "Fingerprint (SHA-256)"}

	// CertMetadataKeyFingerprintSHA1 is the key for the SHA1 fingerprint.
	CertMetadataKeyFingerprintSHA1 = MetadataKey{prefix: CertMetadataPrefix, key: "Fingerprint (SHA1)"}
)
