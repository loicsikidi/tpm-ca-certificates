package certificates

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/concurrency"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/download"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/format"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/vendors"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
	"github.com/spf13/cobra"
)

type addOptions struct {
	configPath    string
	vendorID      string
	name          string
	url           string
	fingerprint   string
	hashAlgorithm string
	concurrency   int
}

func newAddCommand() *cobra.Command {
	opts := &addOptions{}

	cmd := &cobra.Command{
		Use:   "add",
		Short: "add one or more certificates in the configuration file",
		Long: `Add one or more certificates to a vendor's certificate list in the .tpm-roots.yaml file.

The certificates will be downloaded from the provided URL(s), validated, and added to the
specified vendor in alphabetical order by name.

Multiple URLs can be provided by separating them with commas. When multiple URLs are provided:
  - Certificate names are automatically deduced from the certificate CN (Common Name)
  - Fingerprints are calculated automatically (SHA256) or can be provided as comma-separated values
  - Downloads are processed in parallel (use -j to control concurrency, max 10 workers)
  - Individual failures don't prevent other certificates from being added

If no fingerprint is provided, it will be calculated automatically using the specified
hash algorithm (default: SHA256). Use -a to specify a different algorithm (sha1, sha256, sha384, sha512).`,
		Example: `  # Add a single certificate with automatic SHA256 fingerprint
  tpmtb config certificates add -i STM -u "https://example.com/cert.crt" -n "My Certificate"

  # Add a certificate with automatic SHA512 fingerprint
  tpmtb config certificates add -i STM -u "https://example.com/cert.crt" -n "My Certificate" -a sha512

  # Add a certificate with a specific SHA256 fingerprint
  tpmtb config certificates add -i STM -u "https://example.com/cert.crt" -n "My Certificate" -f "SHA256:AB:CD:EF:..."

  # Add multiple certificates (names deduced from CN) with SHA384
  tpmtb config certificates add -i STM -u "https://example.com/cert1.crt,https://example.com/cert2.crt" -a sha384

  # Add multiple certificates with specific SHA256 fingerprints
  tpmtb config certificates add -i STM -u "https://example.com/cert1.crt,https://example.com/cert2.crt" -f "SHA256:AB:CD:...,SHA256:12:34:..."`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAdd(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.configPath, "config", "c", ".tpm-roots.yaml", "Path to the configuration file")
	cmd.Flags().StringVarP(&opts.vendorID, "vendor-id", "i", "", "Vendor ID to add the certificate to")
	cmd.Flags().StringVarP(&opts.name, "name", "n", "", "Name of the certificate (optional when multiple URLs provided, ignored for multiple URLs)")
	cmd.Flags().StringVarP(&opts.url, "url", "u", "", "URL(s) of the certificate(s) to download (comma-separated for multiple)")
	cmd.Flags().StringVarP(&opts.fingerprint, "fingerprint", "f", "", "Fingerprint(s) in format HASH_ALG:HASH (comma-separated for multiple URLs)")
	cmd.Flags().StringVarP(&opts.hashAlgorithm, "hash-algorithm", "a", "sha256", "Hash algorithm to use for fingerprint calculation (sha1, sha256, sha384, sha512)")
	cmd.Flags().IntVarP(&opts.concurrency, "workers", "j", 0,
		fmt.Sprintf("Number of workers to use for parallel downloads (0=auto-detect, max=%d)", concurrency.MaxWorkers))

	cmd.MarkFlagRequired("vendor-id")
	cmd.MarkFlagRequired("url")

	return cmd
}

type certDownloadResult struct {
	url         string
	cert        *x509.Certificate
	fingerprint string
	err         error
}

func runAdd(opts *addOptions) error {
	if err := vendors.ValidateVendorID(opts.vendorID); err != nil {
		return err
	}

	if opts.concurrency > concurrency.MaxWorkers {
		return fmt.Errorf("concurrency value %d exceeds maximum allowed (%d)", opts.concurrency, concurrency.MaxWorkers)
	}

	hashAlgo := strings.ToLower(opts.hashAlgorithm)
	validAlgos := []string{"sha1", "sha256", "sha384", "sha512"}
	if !slices.Contains(validAlgos, hashAlgo) {
		return fmt.Errorf("invalid hash algorithm '%s', must be one of: %s", opts.hashAlgorithm, strings.Join(validAlgos, ", "))
	}

	if opts.fingerprint != "" {
		// Parse all fingerprints and check they match the specified algorithm
		fpRaw := strings.SplitSeq(opts.fingerprint, ",")
		for fp := range fpRaw {
			trimmed := strings.TrimSpace(fp)
			if trimmed == "" {
				continue
			}
			alg, _, err := parseFingerprint(trimmed)
			if err != nil {
				return fmt.Errorf("invalid fingerprint format: %w", err)
			}
			if strings.ToLower(alg) != hashAlgo {
				return fmt.Errorf("fingerprint algorithm '%s' does not match specified hash algorithm '%s'", alg, hashAlgo)
			}
		}
	}

	cfg, err := config.LoadConfig(opts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	vendorIdx := -1
	for i, v := range cfg.Vendors {
		if v.ID == opts.vendorID {
			vendorIdx = i
			break
		}
	}
	if vendorIdx == -1 {
		return fmt.Errorf("vendor with ID '%s' not found", opts.vendorID)
	}

	// Parse URLs (trim whitespace)
	urlsRaw := strings.Split(opts.url, ",")
	urls := make([]string, 0, len(urlsRaw))
	for _, u := range urlsRaw {
		trimmed := strings.TrimSpace(u)
		if trimmed != "" {
			urls = append(urls, trimmed)
		}
	}

	if len(urls) == 0 {
		return fmt.Errorf("no valid URLs provided")
	}

	var fingerprints []string
	if opts.fingerprint != "" {
		fpRaw := strings.Split(opts.fingerprint, ",")
		for _, fp := range fpRaw {
			trimmed := strings.TrimSpace(fp)
			if trimmed != "" {
				fingerprints = append(fingerprints, trimmed)
			}
		}

		if len(fingerprints) != len(urls) {
			return fmt.Errorf("number of fingerprints (%d) doesn't match number of URLs (%d)", len(fingerprints), len(urls))
		}
	}

	// Warn if multiple URLs provided with -n flag
	if len(urls) > 1 && opts.name != "" {
		fmt.Fprintf(os.Stderr, "⚠️  Multiple URLs provided, ignoring -n flag (names will be deduced from certificate CN)\n")
	}

	// Determine worker count
	workers := opts.concurrency
	if workers == 0 {
		workers = concurrency.DetectCPUCount()
	}

	// Download certificates in parallel (works for single URL too)
	results := downloadCertificatesParallel(urls, fingerprints, hashAlgo, workers)

	// Process results
	var successCount, failCount int
	var successfulCerts []config.Certificate
	var failures []struct {
		url string
		err error
	}

	for _, result := range results {
		if result.err != nil {
			failCount++
			failures = append(failures, struct {
				url string
				err error
			}{result.url, result.err})
			continue
		}

		// Determine certificate name
		certName := opts.name
		if certName == "" {
			certName = extractCertificateName(result.cert)
			if certName == "" {
				failCount++
				failures = append(failures, struct {
					url string
					err error
				}{result.url, fmt.Errorf("certificate CN is empty, please provide a name with -n flag")})
				continue
			}
			if len(urls) == 1 {
				fmt.Fprintf(os.Stderr, "⚠️  No name provided, using certificate CN: %s\n", certName)
			}
		}

		// Check if certificate already exists (by URL)
		if certificateExists(cfg.Vendors[vendorIdx].Certificates, result.url) {
			failCount++
			failures = append(failures, struct {
				url string
				err error
			}{result.url, fmt.Errorf("certificate already exists")})
			continue
		}

		// Create certificate entry with fingerprint in appropriate field
		var fingerprintValidation config.Fingerprint
		switch hashAlgo {
		case "sha1":
			fingerprintValidation.SHA1 = result.fingerprint
		case "sha256":
			fingerprintValidation.SHA256 = result.fingerprint
		case "sha384":
			fingerprintValidation.SHA384 = result.fingerprint
		case "sha512":
			fingerprintValidation.SHA512 = result.fingerprint
		}

		newCert := config.Certificate{
			Name: certName,
			URL:  result.url,
			Validation: config.Validation{
				Fingerprint: fingerprintValidation,
			},
		}

		successfulCerts = append(successfulCerts, newCert)
		successCount++
	}

	// Add successful certificates to config
	for _, cert := range successfulCerts {
		cfg.Vendors[vendorIdx].Certificates = insertCertificateAlphabetically(
			cfg.Vendors[vendorIdx].Certificates,
			cert,
		)
	}

	// Save and format configuration if at least one certificate was added
	if successCount > 0 {
		if err := config.SaveConfig(opts.configPath, cfg); err != nil {
			return fmt.Errorf("failed to save configuration: %w", err)
		}

		formatter := format.NewFormatter()
		if err := formatter.FormatFile(opts.configPath, opts.configPath); err != nil {
			return fmt.Errorf("failed to format configuration: %w", err)
		}
	}

	// Print results
	if len(urls) == 1 {
		// Single URL: simple output
		if successCount > 0 {
			fmt.Printf("✅ Certificate '%s' added successfully to vendor '%s'\n", successfulCerts[0].Name, opts.vendorID)
		}
	} else {
		// Multiple URLs: detailed output
		fmt.Printf("\n")
		fmt.Printf("✅ %d/%d certificates added successfully to vendor '%s'\n", successCount, len(urls), opts.vendorID)

		if successCount > 0 {
			fmt.Printf("\nSuccessfully added:\n")
			for _, cert := range successfulCerts {
				fmt.Printf("  • %s\n", cert.Name)
			}
		}

		if failCount > 0 {
			fmt.Printf("\n❌ Failed (%d):\n", failCount)
			for _, f := range failures {
				fmt.Printf("  • %s - %v\n", f.url, f.err)
			}
		}
	}

	if successCount == 0 {
		return fmt.Errorf("no certificates were added")
	}

	return nil
}

// downloadCertificatesParallel downloads multiple certificates in parallel with a goroutine limit.
func downloadCertificatesParallel(urls []string, fingerprints []string, hashAlgo string, maxWorkers int) []certDownloadResult {
	type downloadInput struct {
		url         string
		fingerprint string
	}

	inputs := make([]downloadInput, len(urls))
	for i, url := range urls {
		inputs[i] = downloadInput{url: url}
		if i < len(fingerprints) {
			inputs[i].fingerprint = fingerprints[i]
		}
	}

	return concurrency.Execute(maxWorkers, inputs, func(idx int, input downloadInput) certDownloadResult {
		result := certDownloadResult{url: input.url}

		// Download certificate
		client := download.NewClient()
		cert, err := client.DownloadCertificate(input.url)
		if err != nil {
			result.err = err
			return result
		}

		result.cert = cert

		// Handle fingerprint
		var fpValidation string
		if input.fingerprint != "" {
			// Verify provided fingerprint
			alg, hash, err := parseFingerprint(input.fingerprint)
			if err != nil {
				result.err = fmt.Errorf("invalid fingerprint: %w", err)
				return result
			}

			if err := verifyFingerprint(cert, alg, hash); err != nil {
				result.err = fmt.Errorf("fingerprint verification failed: %w", err)
				return result
			}

			fpValidation = hash
		} else {
			// Calculate fingerprint using specified algorithm
			hashStr, err := calculateFingerprint(cert.Raw, hashAlgo)
			if err != nil {
				result.err = fmt.Errorf("failed to calculate fingerprint: %w", err)
				return result
			}
			fpValidation = hashStr

			// Show warning only for single URL (not cluttering output for multi-URL)
			if len(urls) == 1 {
				fmt.Fprintf(os.Stderr, "⚠️  No fingerprint provided, calculating %s fingerprint automatically\n", strings.ToUpper(hashAlgo))
			}
		}
		result.fingerprint = fpValidation

		return result
	})
}

// extractCertificateName extracts the certificate name from its CN (Common Name).
func extractCertificateName(cert *x509.Certificate) string {
	return strings.TrimSpace(cert.Subject.CommonName)
}

// certificateExists checks if a certificate with the given URL already exists in the list.
func certificateExists(certs []config.Certificate, url string) bool {
	for _, cert := range certs {
		if cert.URL == url {
			return true
		}
	}
	return false
}

// parseFingerprint parses a fingerprint string in format "HASH_ALG:HASH".
func parseFingerprint(fp string) (string, string, error) {
	parts := strings.SplitN(fp, ":", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("fingerprint must be in format HASH_ALG:HASH")
	}

	alg := strings.ToLower(parts[0])
	hash := strings.ToUpper(parts[1])

	// Validate algorithm
	validAlgs := map[string]bool{
		"sha1": true, "sha256": true, "sha384": true, "sha512": true,
	}
	if !validAlgs[alg] {
		return "", "", fmt.Errorf("unsupported hash algorithm '%s', must be one of: sha1, sha256, sha384, sha512", parts[0])
	}

	return alg, hash, nil
}

// formatFingerprint formats a hex string into the colon-separated format.
func formatFingerprint(hexStr string) string {
	var result strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			result.WriteString(":")
		}
		result.WriteString(hexStr[i : i+2])
	}
	return result.String()
}

// verifyFingerprint checks if the provided fingerprint matches the certificate.
func verifyFingerprint(cert *x509.Certificate, alg, expectedHash string) error {
	var actualHash string

	switch strings.ToLower(alg) {
	case "sha1":
		hash := digest.Sha1Hash(cert.Raw)
		actualHash = strings.ToUpper(formatFingerprint(hex.EncodeToString(hash)))
	case "sha256":
		hash := digest.Sha256Hash(cert.Raw)
		actualHash = strings.ToUpper(formatFingerprint(hex.EncodeToString(hash)))
	case "sha384":
		hash := digest.Sha384Hash(cert.Raw)
		actualHash = strings.ToUpper(formatFingerprint(hex.EncodeToString(hash)))
	case "sha512":
		hash := digest.Sha512Hash(cert.Raw)
		actualHash = strings.ToUpper(formatFingerprint(hex.EncodeToString(hash)))
	default:
		return fmt.Errorf("unsupported hash algorithm: %s", alg)
	}

	if actualHash != strings.ToUpper(expectedHash) {
		return fmt.Errorf("fingerprint mismatch: expected %s, got %s", expectedHash, actualHash)
	}

	return nil
}

// calculateFingerprint calculates the fingerprint of data using the specified hash algorithm.
func calculateFingerprint(data []byte, algorithm string) (string, error) {
	var hashBytes []byte

	switch strings.ToLower(algorithm) {
	case "sha1":
		hashBytes = digest.Sha1Hash(data)
	case "sha256":
		hashBytes = digest.Sha256Hash(data)
	case "sha384":
		hashBytes = digest.Sha384Hash(data)
	case "sha512":
		hashBytes = digest.Sha512Hash(data)
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	return strings.ToUpper(formatFingerprint(hex.EncodeToString(hashBytes))), nil
}

// insertCertificateAlphabetically inserts a certificate in alphabetical order by name.
func insertCertificateAlphabetically(certs []config.Certificate, newCert config.Certificate) []config.Certificate {
	insertIdx := len(certs)
	for i, cert := range certs {
		if strings.ToLower(newCert.Name) < strings.ToLower(cert.Name) {
			insertIdx = i
			break
		}
	}

	// Insert at the correct position
	certs = append(certs[:insertIdx], append([]config.Certificate{newCert}, certs[insertIdx:]...)...)
	return certs
}
