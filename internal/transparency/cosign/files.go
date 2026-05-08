package cosign

import (
	"fmt"
	"path/filepath"

	"github.com/loicsikidi/go-utils/system/fsutil"
)

const (
	checksumsFilename = "checksums.txt"
	signatureFilename = "checksums.txt.sigstore.json"
)

// FindChecksumFiles searches for checksum files in a given directory.
//
// It looks for two files:
//   - checksums.txt: The checksums file
//   - checksums.txt.sigstore.json: The Sigstore bundle signature
func FindChecksumFiles(bundleDirPath string) (checksumPath, signaturePath string, found bool) {
	checksumPath = filepath.Join(bundleDirPath, checksumsFilename)
	signaturePath = filepath.Join(bundleDirPath, signatureFilename)

	checksumExists := fsutil.FileExists(checksumPath)
	signatureExists := fsutil.FileExists(signaturePath)

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
	if !fsutil.FileExists(checksumPath) {
		return fmt.Errorf("checksums file not found: %s", checksumPath)
	}
	if !fsutil.FileExists(signaturePath) {
		return fmt.Errorf("signature file not found: %s", signaturePath)
	}
	return nil
}
