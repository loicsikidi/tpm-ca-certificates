package certificates

import (
	"crypto/x509"
	"fmt"
	"slices"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/loicsikidi/tpm-ca-certificates/internal/concurrency"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/download"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/format"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/validate"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/vendors"
	"github.com/loicsikidi/tpm-ca-certificates/internal/fingerprint"
	"github.com/spf13/cobra"
)

const (
	sha1   = "sha1"
	sha256 = "sha256"
	sha384 = "sha384"
	sha512 = "sha512"
)

// AddOptions holds options for the add command.
type AddOptions struct {
	ConfigPath    string
	VendorID      string
	Name          string
	URL           string
	Fingerprint   string
	HashAlgorithm string
	Concurrency   int
}

func newAddCommand() *cobra.Command {
	opts := &AddOptions{}

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
			return RunAdd(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.ConfigPath, "config", "c", ".tpm-roots.yaml", "Path to the configuration file")
	cmd.Flags().StringVarP(&opts.VendorID, "vendor-id", "i", "", "Vendor ID to add the certificate to")
	cmd.Flags().StringVarP(&opts.Name, "name", "n", "", "Name of the certificate (optional when multiple URLs provided, ignored for multiple URLs)")
	cmd.Flags().StringVarP(&opts.URL, "url", "u", "", "URL(s) of the certificate(s) to download (comma-separated for multiple)")
	cmd.Flags().StringVarP(&opts.Fingerprint, "fingerprint", "f", "", "Fingerprint(s) in format HASH_ALG:HASH (comma-separated for multiple URLs)")
	cmd.Flags().StringVarP(&opts.HashAlgorithm, "hash-algorithm", "a", "sha256", "Hash algorithm to use for fingerprint calculation (sha1, sha256, sha384, sha512)")
	cmd.Flags().IntVarP(&opts.Concurrency, "workers", "j", 0,
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

// RunAdd executes the add command with the given options.
func RunAdd(opts *AddOptions) error {
	hashAlgo, urls, fingerprints, err := validateAndPrepareInputs(opts)
	if err != nil {
		return err
	}

	cfg, vendorIdx, err := loadConfigAndFindVendor(opts.ConfigPath, opts.VendorID)
	if err != nil {
		return err
	}

	workers := opts.Concurrency
	if workers == 0 {
		workers = concurrency.DetectCPUCount()
	}
	results := downloadCertificatesParallel(urls, fingerprints, hashAlgo, workers)

	successfulCerts, failures := processDownloadResults(results, cfg.Vendors[vendorIdx].Certificates, opts.Name, hashAlgo, len(urls))

	if len(successfulCerts) > 0 {
		for _, cert := range successfulCerts {
			cfg.Vendors[vendorIdx].Certificates = InsertCertificateAlphabetically(
				cfg.Vendors[vendorIdx].Certificates,
				cert,
			)
		}

		if err := saveAndFormatConfig(opts.ConfigPath, cfg); err != nil {
			return err
		}
	}

	return displayResults(successfulCerts, failures, len(urls), opts.VendorID)
}

// validateAndPrepareInputs validates options and prepares URLs and fingerprints.
func validateAndPrepareInputs(opts *AddOptions) (hashAlgo string, urls, fingerprints []string, err error) {
	if err := vendors.ValidateVendorID(opts.VendorID); err != nil {
		return "", nil, nil, err
	}

	if opts.Concurrency > concurrency.MaxWorkers {
		return "", nil, nil, fmt.Errorf("concurrency value %d exceeds maximum allowed (%d)", opts.Concurrency, concurrency.MaxWorkers)
	}

	hashAlgo = strings.ToLower(opts.HashAlgorithm)
	validAlgos := []string{sha1, sha256, sha384, sha512}
	if !slices.Contains(validAlgos, hashAlgo) {
		return "", nil, nil, fmt.Errorf("invalid hash algorithm '%s', must be one of: %s", opts.HashAlgorithm, strings.Join(validAlgos, ", "))
	}

	// Parse and validate fingerprints if provided
	if opts.Fingerprint != "" {
		fpRaw := strings.SplitSeq(opts.Fingerprint, ",")
		for fp := range fpRaw {
			trimmed := strings.TrimSpace(fp)
			if trimmed == "" {
				continue
			}
			alg, _, err := ParseFingerprint(trimmed)
			if err != nil {
				return "", nil, nil, fmt.Errorf("invalid fingerprint format: %w", err)
			}
			if strings.ToLower(alg) != hashAlgo {
				return "", nil, nil, fmt.Errorf("fingerprint algorithm '%s' does not match specified hash algorithm '%s'", alg, hashAlgo)
			}
			fingerprints = append(fingerprints, trimmed)
		}
	}

	// Parse URLs
	urlsRaw := strings.SplitSeq(opts.URL, ",")
	for u := range urlsRaw {
		trimmed := strings.TrimSpace(u)
		if trimmed != "" {
			urls = append(urls, trimmed)
		}
	}

	if len(urls) == 0 {
		return "", nil, nil, fmt.Errorf("no valid URLs provided")
	}

	if len(fingerprints) > 0 && len(fingerprints) != len(urls) {
		return "", nil, nil, fmt.Errorf("number of fingerprints (%d) doesn't match number of URLs (%d)", len(fingerprints), len(urls))
	}

	// Warn if multiple URLs provided with -n flag
	if len(urls) > 1 && opts.Name != "" {
		cli.DisplayWarning("⚠️  Multiple URLs provided, ignoring -n flag (names will be deduced from certificate CN)")
	}

	return hashAlgo, urls, fingerprints, nil
}

// loadConfigAndFindVendor loads the configuration and finds the vendor index.
func loadConfigAndFindVendor(configPath, vendorID string) (*config.TPMRootsConfig, int, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, -1, fmt.Errorf("failed to load config: %w", err)
	}

	vendorIdx := -1
	for i, v := range cfg.Vendors {
		if v.ID == vendorID {
			vendorIdx = i
			break
		}
	}
	if vendorIdx == -1 {
		return nil, -1, fmt.Errorf("vendor with ID '%s' not found", vendorID)
	}

	return cfg, vendorIdx, nil
}

type downloadFailure struct {
	url string
	err error
}

// processDownloadResults processes download results and creates certificate entries.
func processDownloadResults(results []certDownloadResult, existingCerts []config.Certificate, providedName, hashAlgo string, urlCount int) ([]config.Certificate, []downloadFailure) {
	var successfulCerts []config.Certificate
	var failures []downloadFailure

	for _, result := range results {
		if result.err != nil {
			failures = append(failures, downloadFailure{result.url, result.err})
			continue
		}

		// Determine certificate name
		certName := providedName
		if certName == "" {
			certName = extractCertificateName(result.cert)
			if certName == "" {
				failures = append(failures, downloadFailure{result.url, fmt.Errorf("certificate CN is empty, please provide a name with -n flag")})
				continue
			}
			if urlCount == 1 {
				cli.DisplayWarning("⚠️  No name provided, using certificate CN: %s", certName)
			}
		}

		if err := validate.CheckCertificate(existingCerts, result.url, result.cert); err != nil {
			failures = append(failures, downloadFailure{result.url, err})
			continue
		}

		fingerprintValidation := config.NewFingerprint(hashAlgo, result.fingerprint)
		newCert := config.Certificate{
			Name: certName,
			URL:  result.url,
			Validation: config.Validation{
				Fingerprint: *fingerprintValidation,
			},
		}

		successfulCerts = append(successfulCerts, newCert)
	}

	return successfulCerts, failures
}

// saveAndFormatConfig saves and formats the configuration file.
func saveAndFormatConfig(configPath string, cfg *config.TPMRootsConfig) error {
	if err := config.SaveConfig(configPath, cfg); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	formatter := format.NewFormatter()
	if err := formatter.FormatFile(configPath, configPath); err != nil {
		return fmt.Errorf("failed to format configuration: %w", err)
	}

	return nil
}

// displayResults displays the results of the add operation.
func displayResults(successfulCerts []config.Certificate, failures []downloadFailure, totalURLs int, vendorID string) error {
	successCount := len(successfulCerts)
	failCount := len(failures)

	if totalURLs == 1 {
		// Single URL: simple output
		if successCount > 0 {
			cli.DisplaySuccess("✅ Certificate '%s' added successfully to vendor '%s'", successfulCerts[0].Name, vendorID)
			return nil
		}
		if failCount > 0 {
			cli.DisplayError("❌ Failed to add certificate: %v", failures[0].err)
		}
	} else {
		// Multiple URLs: detailed output
		cli.DisplaySuccess("✅ %d/%d certificates added successfully to vendor '%s'", successCount, totalURLs, vendorID)

		if successCount > 0 {
			fmt.Printf("\nSuccessfully added:\n")
			for _, cert := range successfulCerts {
				fmt.Printf("  • %s\n", cert.Name)
			}
		}

		if failCount > 0 {
			fmt.Println()
			cli.DisplayError("❌ Failed (%d):", failCount)
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
			alg, hash, err := ParseFingerprint(input.fingerprint)
			if err != nil {
				result.err = fmt.Errorf("invalid fingerprint: %w", err)
				return result
			}

			if err := validate.ValidateFingerprintWithAlgorithm(cert, hash, alg); err != nil {
				result.err = err
				return result
			}

			fpValidation = hash
		} else {
			// Calculate fingerprint using specified algorithm
			fpValidation = fingerprint.New(cert.Raw, hashAlgo)

			// Show warning only for single URL (not cluttering output for multi-URL)
			if len(urls) == 1 {
				cli.DisplayWarning("⚠️  No fingerprint provided, calculating %s fingerprint automatically", strings.ToUpper(hashAlgo))
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

// ParseFingerprint parses a fingerprint string in format "HASH_ALG:HASH".
func ParseFingerprint(fp string) (string, string, error) {
	parts := strings.SplitN(fp, ":", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("fingerprint must be in format HASH_ALG:HASH")
	}

	alg := strings.ToLower(parts[0])
	hash := strings.ToUpper(parts[1])

	// Validate algorithm
	validAlgs := map[string]bool{
		sha1: true, sha256: true, sha384: true, sha512: true,
	}
	if !validAlgs[alg] {
		return "", "", fmt.Errorf("unsupported hash algorithm '%s', must be one of: sha1, sha256, sha384, sha512", parts[0])
	}

	return alg, hash, nil
}

// InsertCertificateAlphabetically inserts a certificate in alphabetical order by name.
func InsertCertificateAlphabetically(certs []config.Certificate, newCert config.Certificate) []config.Certificate {
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
