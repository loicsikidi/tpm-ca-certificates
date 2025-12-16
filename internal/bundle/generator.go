package bundle

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/loicsikidi/tpm-ca-certificates/internal/concurrency"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/download"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/validate"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

// Generator orchestrates the generation of a TPM trust bundle.
type Generator struct {
	downloader *download.Client
}

// NewGenerator creates a new bundle generator.
func NewGenerator(optionalClient ...utils.HttpClient) *Generator {
	return &Generator{
		downloader: download.NewClient(optionalClient...),
	}
}

// Generate creates a PEM-encoded trust bundle from the configuration.
//
// It downloads all certificates, validates their fingerprints, converts them to PEM format,
// and concatenates them into a single bundle.
//
// The process fails immediately on the first error (fail-fast approach).
//
// Example:
//
//	gen := bundle.NewGenerator()
//	pemBundle, err := gen.Generate(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(pemBundle)
func (g *Generator) Generate(cfg *config.TPMRootsConfig) (string, error) {
	return g.GenerateWithConcurrency(cfg, 1)
}

// GenerateWithConcurrency creates a PEM-encoded trust bundle with concurrent vendor processing.
//
// It processes vendors in parallel (up to 'workers' vendors at once) while maintaining
// the certificate order from the configuration file.
// If workers is 0, it auto-detects the optimal count.
// The number of workers is capped at [concurrency.MaxWorkers].
//
// Each certificate PEM block is prefixed with a comment containing the certificate name.
//
// Example:
//
//	gen := bundle.NewGenerator()
//	pemBundle, err := gen.GenerateWithConcurrency(cfg, 4)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(pemBundle)
func (g *Generator) GenerateWithConcurrency(cfg *config.TPMRootsConfig, workers int) (string, error) {
	return g.GenerateWithConcurrencyAndOutput(cfg, workers, "")
}

// GenerateWithConcurrencyAndOutput creates a PEM-encoded trust bundle with concurrent vendor processing.
//
// It processes vendors in parallel (up to 'workers' vendors at once) while maintaining
// the certificate order from the configuration file.
// If workers is 0, it auto-detects the optimal count.
// The number of workers is capped at [concurrency.MaxWorkers].
//
// The outputPath parameter is used to include the filename in the bundle header.
// If outputPath is empty, no filename is included in the header.
//
// Example:
//
//	gen := bundle.NewGenerator()
//	pemBundle, err := gen.GenerateWithConcurrencyAndOutput(cfg, 4, "bundle.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(pemBundle)
func (g *Generator) GenerateWithConcurrencyAndOutput(cfg *config.TPMRootsConfig, workers int, outputPath string) (string, error) {
	return g.GenerateWithMetadata(cfg, workers, outputPath, "", "")
}

// GenerateWithMetadata creates a PEM-encoded trust bundle with concurrent vendor processing and git metadata.
//
// It processes vendors in parallel (up to 'workers' vendors at once) while maintaining
// the certificate order from the configuration file.
// If workers is 0, it auto-detects the optimal count.
// The number of workers is capped at [concurrency.MaxWorkers].
//
// The outputPath parameter is used to include the filename in the bundle header.
// The date and commit parameters are included in the bundle global metadata.
// If outputPath is empty, no filename is included in the header.
//
// Example:
//
//	gen := bundle.NewGenerator()
//	pemBundle, err := gen.GenerateWithMetadata(cfg, 4, "bundle.pem", "2024-06-15", "a1b2c3d...")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(pemBundle)
func (g *Generator) GenerateWithMetadata(cfg *config.TPMRootsConfig, workers int, outputPath, date, commit string) (string, error) {
	if workers == 0 {
		workers = concurrency.DetectCPUCount()
	}
	if workers > concurrency.MaxWorkers {
		workers = concurrency.MaxWorkers
	}
	if workers < 1 {
		workers = 1
	}

	// Prepare result storage that maintains order
	type certResult struct {
		certIdx  int
		pemBlock string
	}

	type vendorResult struct {
		vendorIdx int
		certs     []certResult
		err       error
	}

	// Create a channel to limit concurrent vendor processing
	vendorChan := make(chan int, workers)

	results := make([]vendorResult, len(cfg.Vendors))
	var wg sync.WaitGroup

	// Process each vendor concurrently
	for vendorIdx, vendor := range cfg.Vendors {
		wg.Add(1)
		go func(vIdx int, v config.Vendor) {
			defer wg.Done()

			// Acquire worker slot
			vendorChan <- 1
			defer func() { <-vendorChan }()

			certs := make([]certResult, len(v.Certificates))

			// Process certificates for this vendor sequentially to maintain order
			for certIdx, cert := range v.Certificates {
				pemBlock, err := g.processCertificate(cert, v.ID)
				if err != nil {
					results[vIdx] = vendorResult{
						vendorIdx: vIdx,
						err: fmt.Errorf("failed to process certificate %q from vendor %q: %w",
							cert.Name, v.Name, err),
					}
					return
				}
				certs[certIdx] = certResult{
					certIdx:  certIdx,
					pemBlock: pemBlock,
				}
			}

			results[vIdx] = vendorResult{
				vendorIdx: vIdx,
				certs:     certs,
			}
		}(vendorIdx, vendor)
	}

	wg.Wait()

	// Check for errors and build final output in order
	var pemBlocks []string
	for _, result := range results {
		if result.err != nil {
			return "", result.err
		}
		for _, cert := range result.certs {
			pemBlocks = append(pemBlocks, cert.pemBlock)
		}
	}

	// Build final bundle with header
	var bundle strings.Builder
	bundle.WriteString(buildBundleHeader(outputPath, date, commit))
	bundle.WriteString(strings.Join(pemBlocks, "\n"))

	return bundle.String(), nil
}

// processCertificate downloads, validates, and converts a certificate to PEM with a comment header.
func (g *Generator) processCertificate(cert config.Certificate, vendorID string) (string, error) {
	x509Cert, err := g.downloader.DownloadCertificate(cert.URL)
	if err != nil {
		return "", err
	}

	if err := validate.ValidateFingerprint(x509Cert, cert.Validation.Fingerprint); err != nil {
		return "", fmt.Errorf("fingerprint validation failed: %w", err)
	}

	pemBlock := EncodePEM(x509Cert)
	header := buildCertificateHeader(x509Cert, cert.Name, vendorID)

	return fmt.Sprintf("%s%s", header, pemBlock), nil
}

// EncodePEM converts an x509 certificate to PEM format.
func EncodePEM(cert *x509.Certificate) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(block)
}

// buildCertificateHeader creates a comment header with certificate details.
//
// Note: see section 2. from docs/specifications/04-tpm-trust-bundle-format.md for format details.
func buildCertificateHeader(cert *x509.Certificate, name string, vendorID string) string {
	sha256Hash := sha256.Sum256(cert.Raw)
	sha1Hash := sha1.Sum(cert.Raw)

	var header strings.Builder
	header.WriteString("#\n")
	header.WriteString(fmt.Sprintf("# Certificate: %s\n", name))
	header.WriteString(fmt.Sprintf("# Owner: %s\n", vendorID))
	header.WriteString("#\n")
	header.WriteString(fmt.Sprintf("# Issuer: %s\n", cert.Issuer.String()))
	header.WriteString(fmt.Sprintf("# Serial Number: %d (%#x)\n", cert.SerialNumber, cert.SerialNumber))
	header.WriteString(fmt.Sprintf("# Subject: %s\n", cert.Subject.String()))
	header.WriteString(fmt.Sprintf("# Not Valid Before: %s\n", cert.NotBefore.Format("Mon Jan 02 15:04:05 2006")))
	header.WriteString(fmt.Sprintf("# Not Valid After : %s\n", cert.NotAfter.Format("Mon Jan 02 15:04:05 2006")))
	header.WriteString(fmt.Sprintf("# Fingerprint (SHA-256): %s\n", formatFingerprint(sha256Hash[:])))
	header.WriteString(fmt.Sprintf("# Fingerprint (SHA1): %s\n", formatFingerprint(sha1Hash[:])))

	return header.String()
}

// formatFingerprint formats a hash as a colon-separated uppercase hex string.
func formatFingerprint(hash []byte) string {
	hexStr := strings.ToUpper(hex.EncodeToString(hash))
	var formatted strings.Builder

	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			formatted.WriteString(":")
		}
		formatted.WriteString(hexStr[i : i+2])
	}

	return formatted.String()
}

// buildBundleHeader creates the header for the certificate bundle.
//
// Note: see section 1. from docs/specifications/04-tpm-trust-bundle-format.md for format details.
func buildBundleHeader(outputPath, date, commit string) string {
	var header strings.Builder
	header.WriteString("##\n")

	if outputPath != "" {
		filename := filepath.Base(outputPath)
		header.WriteString(fmt.Sprintf("## %s\n", filename))
	} else {
		header.WriteString("## tpm-ca-certificates.pem\n")
	}

	header.WriteString("##\n")

	if date != "" {
		header.WriteString(fmt.Sprintf("## Date: %s\n", date))
	}
	if commit != "" {
		header.WriteString(fmt.Sprintf("## Commit: %s\n", commit))
	}

	header.WriteString("##\n")
	header.WriteString("## This file has been auto-generated by tpmtb (TPM Trust Bundle)\n")
	header.WriteString("## and contains a list of verified TPM Root Endorsement Certificates.\n")
	header.WriteString("##\n")
	header.WriteString("\n")
	return header.String()
}
