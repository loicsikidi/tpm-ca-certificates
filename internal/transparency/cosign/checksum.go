package cosign

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ValidateChecksum verifies that the artifact's checksum matches the one in the checksums file.
//
// The checksums file format is:
//
//	<sha256-hex>  <filename>
//
// Parameters:
//   - checksumPath: Path to the checksums.txt file
//   - artifactPath: Path to the artifact file to verify
//
// Returns an error if:
//   - The checksums file cannot be read or parsed
//   - The artifact is not found in the checksums file
//   - The artifact's checksum doesn't match the expected value
func ValidateChecksum(checksumPath, artifactPath string) error {
	// Parse the checksums file to extract the expected checksum
	expectedChecksum, err := parseChecksumFile(checksumPath, artifactPath)
	if err != nil {
		return err
	}

	// Compute the actual checksum of the artifact
	actualChecksum, err := computeFileSHA256(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to compute artifact checksum: %w", err)
	}

	// Compare checksums
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s",
			filepath.Base(artifactPath), expectedChecksum, actualChecksum)
	}

	return nil
}

// parseChecksumFile parses a checksums.txt file and extracts the checksum for the specified artifact.
//
// The file format is:
//
//	<sha256-hex>  <filename>
//	<sha256-hex>  <filename>
//	...
//
// It returns the checksum (as lowercase hex string) for the artifact.
func parseChecksumFile(checksumPath, artifactPath string) (string, error) {
	file, err := os.Open(checksumPath)
	if err != nil {
		return "", fmt.Errorf("failed to open checksums file: %w", err)
	}
	defer file.Close()

	// Get the base name of the artifact to search for
	artifactBasename := filepath.Base(artifactPath)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse line: "<checksum>  <filename>"
		// Note: checksums.txt typically uses two spaces between checksum and filename
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		checksum := parts[0]
		filename := parts[1]

		if filename == artifactBasename {
			return strings.ToLower(checksum), nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading checksums file: %w", err)
	}

	return "", fmt.Errorf("artifact %s not found in checksums file", artifactBasename)
}

// computeFileSHA256 computes the SHA-256 checksum of a file.
//
// Returns the checksum as a lowercase hex string.
func computeFileSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
