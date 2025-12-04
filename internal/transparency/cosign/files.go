package cosign

import (
	"fmt"
	"path/filepath"

	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
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

	checksumExists := utils.FileExists(checksumPath)
	signatureExists := utils.FileExists(signaturePath)

	if checksumExists && signatureExists {
		return checksumPath, signaturePath, true
	}

	// If one or both don't exist, return empty paths
	return "", "", false
}

// ValidateChecksumFilesExist validates that the specified checksum files exist.
//
// This is a helper function to verify that user-provided paths are valid.
func ValidateChecksumFilesExist(checksumPath, signaturePath string) error {
	if !utils.FileExists(checksumPath) {
		return fmt.Errorf("checksums file not found: %s", checksumPath)
	}
	if !utils.FileExists(signaturePath) {
		return fmt.Errorf("signature file not found: %s", signaturePath)
	}
	return nil
}
