package digest

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

// ComputeSHA256 computes the SHA-256 digest from a byte slice.
//
// The returned digest is in the format "sha256:HEX" where HEX is the lowercase
// hexadecimal representation of the hash.
func ComputeSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	return fmt.Sprintf("sha256:%s", digest)
}

// Sha1Hash computes the SHA1 hash of the input data.
func Sha1Hash(data []byte) []byte {
	hash := sha1.Sum(data)
	return hash[:]
}

// Sha256Hash computes the SHA256 hash of the input data.
func Sha256Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// Sha384Hash computes the SHA384 hash of the input data.
func Sha384Hash(data []byte) []byte {
	hash := sha512.Sum384(data)
	return hash[:]
}

// Sha512Hash computes the SHA512 hash of the input data.
func Sha512Hash(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}
