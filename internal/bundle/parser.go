package bundle

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config/vendors"
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

// ParseBundle parses a PEM-encoded TPM trust bundle and extracts certificates organized by vendor.
//
// The function reads the bundle format as specified in docs/specifications/04-tpm-trust-bundle-format.md
// and extracts the Owner field from certificate metadata to determine vendor ownership.
//
// Example:
//
//	catalog, err := bundle.ParseBundle(bundleData)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for vendorID, certs := range catalog {
//	    fmt.Printf("Vendor %s has %d certificates\n", vendorID, len(certs))
//	}
func ParseBundle(data []byte) (map[vendors.ID][]*x509.Certificate, error) {
	return ParseBundleFromReader(bytes.NewReader(data))
}

// ParseBundleFromReader reads a PEM-encoded TPM trust bundle from an [io.Reader]
// and extracts certificates organized by vendor.
func ParseBundleFromReader(reader io.Reader) (map[vendors.ID][]*x509.Certificate, error) {
	catalog := make(map[vendors.ID][]*x509.Certificate)
	scanner := bufio.NewScanner(reader)

	var currentOwner vendors.ID
	var pemBlock strings.Builder
	inPEMBlock := false

	for scanner.Scan() {
		line := scanner.Text()

		// Skip global metadata (lines starting with ##)
		if strings.HasPrefix(line, "##") {
			continue
		}

		// Parse certificate metadata (lines starting with #)
		if strings.HasPrefix(line, "# Owner: ") {
			ownerStr := strings.TrimSpace(strings.TrimPrefix(line, "# Owner:"))
			currentOwner = vendors.ID(ownerStr)
			if err := currentOwner.Validate(); err != nil {
				return nil, fmt.Errorf("invalid vendor ID in certificate metadata: %w", err)
			}
			continue
		}

		// Skip other metadata lines
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Handle PEM blocks
		if strings.HasPrefix(line, "-----BEGIN CERTIFICATE-----") {
			inPEMBlock = true
			pemBlock.Reset()
			pemBlock.WriteString(line)
			pemBlock.WriteString("\n")
			continue
		}

		if inPEMBlock {
			pemBlock.WriteString(line)
			pemBlock.WriteString("\n")

			if strings.HasPrefix(line, "-----END CERTIFICATE-----") {
				inPEMBlock = false

				block, _ := pem.Decode([]byte(pemBlock.String()))
				if block == nil {
					return nil, fmt.Errorf("failed to decode PEM block")
				}

				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse certificate: %w", err)
				}

				if currentOwner == "" {
					return nil, fmt.Errorf("certificate found without owner metadata")
				}

				catalog[currentOwner] = append(catalog[currentOwner], cert)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read bundle: %w", err)
	}

	if len(catalog) == 0 {
		return nil, fmt.Errorf("no certificates found in bundle")
	}

	return catalog, nil
}
