package fingerprint

import (
	"encoding/hex"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
)

const (
	SHA1   = "sha1"
	SHA256 = "sha256"
	SHA384 = "sha384"
	SHA512 = "sha512"
)

// New calculates the fingerprint of data using the specified hash algorithm.
func New(data []byte, algorithm string) string {
	var hashBytes []byte

	switch strings.ToLower(algorithm) {
	case SHA1:
		hashBytes = digest.Sha1Hash(data)
	case SHA256:
		hashBytes = digest.Sha256Hash(data)
	case SHA384:
		hashBytes = digest.Sha384Hash(data)
	case SHA512:
		hashBytes = digest.Sha512Hash(data)
	default:
		// This should not happen due to prior validation
		panic("unsupported hash algorithm: " + algorithm)
	}

	return strings.ToUpper(FormatFingerprint(hex.EncodeToString(hashBytes)))
}
