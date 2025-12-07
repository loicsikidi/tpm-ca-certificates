package cosign

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
)

// ValidateChecksum verifies that the artifact's checksum matches the one in the checksums.
func ValidateChecksum(checksumData, artifactData []byte, artifactName string) error {
	expectedChecksum, err := parseChecksumFile(checksumData, artifactName)
	if err != nil {
		return err
	}

	actualChecksum := computeDataSHA256(artifactData)
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s",
			artifactName, expectedChecksum, actualChecksum)
	}

	return nil
}

// parseChecksumFile parses checksums data and extracts the checksum for the specified artifact.
//
// The file format is:
//
//	<sha256-hex>  <filename>
//	<sha256-hex>  <filename>
func parseChecksumFile(data []byte, artifactName string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
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

		if filename == artifactName {
			return strings.ToLower(checksum), nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading checksums data: %w", err)
	}

	return "", fmt.Errorf("artifact %s not found in checksums data", artifactName)
}

// computeDataSHA256 computes the SHA-256 checksum of data.
//
// Returns the checksum as a lowercase hex string.
func computeDataSHA256(data []byte) string {
	return hex.EncodeToString(digest.Sha256Hash(data))
}
