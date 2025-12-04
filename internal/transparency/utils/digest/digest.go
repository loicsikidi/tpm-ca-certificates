package digest

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// ComputeSHA256 computes the SHA-256 digest of a file.
//
// The returned digest is in the format "sha256:HEX" where HEX is the lowercase
// hexadecimal representation of the hash.
//
// Example:
//
//	digest, err := ComputeSHA256("bundle.pem")
//	if err != nil {
//	    return err
//	}
//	fmt.Println(digest) // "sha256:abc123..."
func ComputeSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to compute hash: %w", err)
	}

	digest := hex.EncodeToString(hash.Sum(nil))
	return fmt.Sprintf("sha256:%s", digest), nil
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
