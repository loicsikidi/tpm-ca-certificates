package bundle

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Metadata represents the global metadata from a TPM trust bundle.
type Metadata struct {
	Date   string
	Commit string
}

// ParseMetadata reads a TPM trust bundle file and extracts the global metadata.
//
// The function expects the bundle to follow the format specified in
// docs/specifications/04-tpm-trust-bundle-format.md with metadata in the header:
//
//	##
//	## tpm-ca-certificates.pem
//	##
//	## Date: 2025-12-04
//	## Commit: 63e6a017e9c15428b2959cb2760d21f05dea42f4
//	##
//
// Returns an error if the file cannot be read or if the bundle does not contain
// the required metadata fields.
//
// Example:
//
//	metadata, err := bundle.ParseMetadata("tpm-ca-certificates.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Date: %s, Commit: %s\n", metadata.Date, metadata.Commit)
func ParseMetadata(bundlePath string) (*Metadata, error) {
	file, err := os.Open(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open bundle file: %w", err)
	}
	defer file.Close()

	var metadata Metadata
	scanner := bufio.NewScanner(file)

	// Parse the header comments (lines starting with ##)
	for scanner.Scan() {
		line := scanner.Text()

		// Stop when we reach the end of the global metadata section
		if !strings.HasPrefix(line, "##") {
			break
		}

		// Look for "## Date: YYYY-MM-DD"
		if strings.HasPrefix(line, "## Date: ") {
			metadata.Date = strings.TrimSpace(strings.TrimPrefix(line, "## Date:"))
		}

		// Look for "## Commit: <hash>"
		if strings.HasPrefix(line, "## Commit: ") {
			metadata.Commit = strings.TrimSpace(strings.TrimPrefix(line, "## Commit:"))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read bundle file: %w", err)
	}

	// Validate that we found the required metadata
	if metadata.Date == "" {
		return nil, fmt.Errorf("bundle does not contain required 'Date' metadata in header")
	}

	if metadata.Commit == "" {
		return nil, fmt.Errorf("bundle does not contain required 'Commit' metadata in header")
	}

	return &metadata, nil
}
