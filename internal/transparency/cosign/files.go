package cosign

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	checksumsFilename = "checksums.txt"
	signatureFilename = "checksums.txt.sigstore.json"
)

// FindChecksumFiles searches for checksum files in the same directory as the bundle.
//
// It looks for two files:
//   - checksums.txt: The checksums file
//   - checksums.txt.sigstore.json: The Sigstore bundle signature
func FindChecksumFiles(bundlePath string) (checksumPath, signaturePath string, found bool) {
	bundleDir := filepath.Dir(bundlePath)

	checksumPath = filepath.Join(bundleDir, checksumsFilename)
	signaturePath = filepath.Join(bundleDir, signatureFilename)

	checksumExists := fileExists(checksumPath)
	signatureExists := fileExists(signaturePath)

	if checksumExists && signatureExists {
		return checksumPath, signaturePath, true
	}

	// If one or both don't exist, return empty paths
	return "", "", false
}

// fileExists checks if a file exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// ValidateChecksumFilesExist validates that the specified checksum files exist.
//
// This is a helper function to verify that user-provided paths are valid.
func ValidateChecksumFilesExist(checksumPath, signaturePath string) error {
	if !fileExists(checksumPath) {
		return fmt.Errorf("checksums file not found: %s", checksumPath)
	}
	if !fileExists(signaturePath) {
		return fmt.Errorf("signature file not found: %s", signaturePath)
	}
	return nil
}
