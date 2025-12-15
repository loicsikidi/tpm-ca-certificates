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

func (m *Metadata) Check() error {
	if m.Date == "" {
		return fmt.Errorf("metadata 'Date' is required")
	}
	if err := ValidateDate(m.Date); err != nil {
		return err
	}
	if m.Commit == "" {
		return fmt.Errorf("metadata 'Commit' is required")
	}
	if err := ValidateCommit(m.Commit); err != nil {
		return err
	}
	return nil
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
		if !strings.HasPrefix(line, GlobalMetadataPrefix) {
			break
		}

		// Look for "## Date: YYYY-MM-DD"
		if after, ok := strings.CutPrefix(line, MetadataKeyDate.String()); ok {
			metadata.Date = strings.TrimSpace(after)
		}

		// Look for "## Commit: <hash>"
		if after, ok := strings.CutPrefix(line, MetadataKeyCommit.String()); ok {
			metadata.Commit = strings.TrimSpace(after)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read bundle: %w", err)
	}

	// Validate that we found the required metadata
	if metadata.Date == "" {
		return nil, fmt.Errorf("bundle does not contain required '%s' metadata in header", MetadataKeyDate.Key())
	}

	if metadata.Commit == "" {
		return nil, fmt.Errorf("bundle does not contain required '%s' metadata in header", MetadataKeyCommit.Key())
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
		if strings.HasPrefix(line, GlobalMetadataPrefix) {
			continue
		}

		// Parse certificate metadata (lines starting with #)
		if after, ok := strings.CutPrefix(line, CertMetadataKeyOwner.String()); ok {
			ownerStr := strings.TrimSpace(after)
			currentOwner = vendors.ID(ownerStr)
			if err := currentOwner.Validate(); err != nil {
				return nil, fmt.Errorf("invalid vendor ID in certificate metadata: %w", err)
			}
			continue
		}

		// Skip other metadata lines
		if strings.HasPrefix(line, CertMetadataPrefix) {
			continue
		}

		// Handle PEM blocks
		if strings.HasPrefix(line, PEMBeginMarker) {
			inPEMBlock = true
			pemBlock.Reset()
			pemBlock.WriteString(line)
			pemBlock.WriteString("\n")
			continue
		}

		if inPEMBlock {
			pemBlock.WriteString(line)
			pemBlock.WriteString("\n")

			if strings.HasPrefix(line, PEMEndMarker) {
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
