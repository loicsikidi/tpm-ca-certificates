package certificates

import (
	"crypto/sha1"
	"crypto/sha512"
)

// sha1Hash computes the SHA1 hash of the input data.
func sha1Hash(data []byte) []byte {
	hash := sha1.Sum(data)
	return hash[:]
}

// sha384Hash computes the SHA384 hash of the input data.
func sha384Hash(data []byte) []byte {
	hash := sha512.Sum384(data)
	return hash[:]
}

// sha512Hash computes the SHA512 hash of the input data.
func sha512Hash(data []byte) []byte {
	hash := sha512.Sum512(data)
	return hash[:]
}
