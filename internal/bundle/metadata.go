package bundle

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
)

// Metadata represents the global metadata from a TPM trust bundle.
type Metadata struct {
	Date   string
	Commit string
}

// ParseMetadata parses a TPM trust bundle from bytes and extracts the global metadata.
func ParseMetadata(data []byte) (*Metadata, error) {
	return ParseMetadataFromReader(bytes.NewReader(data))
}

// ParseMetadataFromReader reads a TPM trust bundle from an [io.Reader] and extracts the global metadata.
func ParseMetadataFromReader(reader io.Reader) (*Metadata, error) {
	var metadata Metadata
	scanner := bufio.NewScanner(reader)

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
		return nil, fmt.Errorf("failed to read bundle: %w", err)
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
