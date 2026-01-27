package certificates

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
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
	URIs          string
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
hash algorithm (default: SHA256). Use -a to specify a different algorithm (sha1, sha256, sha384, sha512).
When a fingerprint is provided, the hash algorithm is automatically inferred from it.`,
		Example: `  # Add a single certificate with automatic SHA256 fingerprint
  tpmtb config certificates add -i STM -u "https://example.com/cert.crt" -n "My Certificate"

  # Add a certificate with automatic SHA512 fingerprint
  tpmtb config certificates add -i STM -u "https://example.com/cert.crt" -n "My Certificate" -a sha512

  # Add a certificate with a specific SHA256 fingerprint
  tpmtb config certificates add -i STM -u "https://example.com/cert.crt" -n "My Certificate" -f "SHA256:AB:CD:EF:..."

  # Add a certificate with a specific SHA512 fingerprint
  tpmtb config certificates add -i STM -u "https://example.com/cert.crt" -n "My Certificate" -f "SHA512:AB:CD:EF:..."

  # Add multiple certificates (names deduced from CN) with SHA384
  tpmtb config certificates add -i STM -u "https://example.com/cert1.crt,https://example.com/cert2.crt" -a sha384

  # Add multiple certificates with specific SHA256 fingerprints
  tpmtb config certificates add -i STM -u "https://example.com/cert1.crt,https://example.com/cert2.crt" -f "SHA256:AB:CD:...,SHA256:12:34:..."`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return Run(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVarP(&opts.ConfigPath, "config", "c", ".tpm-roots.yaml", "Path to the configuration file")
	cmd.Flags().StringVarP(&opts.VendorID, "vendor-id", "i", "", "Vendor ID to add the certificate to")
	cmd.Flags().StringVarP(&opts.Name, "name", "n", "", "Name of the certificate (optional when multiple URLs provided, ignored for multiple URLs)")
	cmd.Flags().StringVarP(&opts.URIs, "uri", "u", "", "URI(s) of the certificate(s) to download (comma-separated for multiple)")
	cmd.Flags().StringVarP(&opts.Fingerprint, "fingerprint", "f", "", "Fingerprint(s) in format HASH_ALG:HASH (comma-separated for multiple URLs)")
	cmd.Flags().StringVarP(&opts.HashAlgorithm, "hash-algorithm", "a", "sha256", "Hash algorithm to use for fingerprint calculation (sha1, sha256, sha384, sha512)")
	cmd.Flags().IntVarP(&opts.Concurrency, "workers", "j", 0,
		fmt.Sprintf("Number of workers to use for parallel downloads (0=auto-detect, max=%d)", concurrency.MaxWorkers))

	cmd.MarkFlagRequired("vendor-id")
	cmd.MarkFlagRequired("url")

	return cmd
}

type certDownloadResult struct {
	uri         string
	cert        *x509.Certificate
	fingerprint string
	err         error
}

// Run executes the add command with the given options.
func Run(ctx context.Context, opts *AddOptions) error {
	hashAlgo, uris, fingerprints, err := validateAndPrepareInputs(opts)
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
	results := downloadCertificatesParallel(ctx, uris, fingerprints, hashAlgo, workers)

	successfulCerts, failures := processDownloadResults(results, cfg.Vendors[vendorIdx].Certificates, opts.Name, hashAlgo, len(uris))

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

	return displayResults(successfulCerts, failures, len(uris), opts.VendorID)
}

// parseAndValidateFingerprints parses fingerprints and infers the hash algorithm.
// Returns the list of parsed fingerprints and the inferred algorithm (empty if no fingerprints provided).
func parseAndValidateFingerprints(fingerprintInput string) (fingerprints []string, inferredAlgo string, err error) {
	if fingerprintInput == "" {
		return nil, "", nil
	}

	fpRaw := strings.SplitSeq(fingerprintInput, ",")
	for fp := range fpRaw {
		trimmed := strings.TrimSpace(fp)
		if trimmed == "" {
			continue
		}
		alg, _, err := ParseFingerprint(trimmed)
		if err != nil {
			return nil, "", fmt.Errorf("invalid fingerprint format: %w", err)
		}

		// First fingerprint sets the expected algorithm
		if inferredAlgo == "" {
			inferredAlgo = strings.ToLower(alg)
		} else if strings.ToLower(alg) != inferredAlgo {
			// All fingerprints must use the same algorithm
			return nil, "", fmt.Errorf("all fingerprints must use the same hash algorithm, found '%s' and '%s'", inferredAlgo, alg)
		}
		fingerprints = append(fingerprints, trimmed)
	}

	return fingerprints, inferredAlgo, nil
}

// determineHashAlgorithm determines the final hash algorithm to use.
// If fingerprints are provided, their algorithm takes precedence over the flag value.
func determineHashAlgorithm(inferredAlgo, flagAlgo string) (string, error) {
	if inferredAlgo != "" {
		// Check if user explicitly set a different algorithm via flag
		if flagAlgo != sha256 && strings.ToLower(flagAlgo) != inferredAlgo {
			cli.DisplayWarning("⚠️  Ignoring --hash-algorithm flag, using '%s' from provided fingerprint(s)", inferredAlgo)
		}
		return inferredAlgo, nil
	}

	hashAlgo := strings.ToLower(flagAlgo)
	validAlgos := []string{sha1, sha256, sha384, sha512}
	if !slices.Contains(validAlgos, hashAlgo) {
		return "", fmt.Errorf("invalid hash algorithm '%s', must be one of: %s", flagAlgo, strings.Join(validAlgos, ", "))
	}
	return hashAlgo, nil
}

// parseAndValidateURIs parses and validates URIs from the input string.
func parseAndValidateURIs(uriInput string) ([]string, error) {
	var uris []string
	urisRaw := strings.SplitSeq(uriInput, ",")
	for u := range urisRaw {
		trimmed := strings.TrimSpace(u)
		if trimmed != "" {
			uris = append(uris, trimmed)
		}
	}

	if len(uris) == 0 {
		return nil, fmt.Errorf("no valid URIs provided")
	}

	// Validate that all URLs use HTTPS or file scheme
	for _, uri := range uris {
		u, err := url.Parse(uri)
		if err != nil {
			return nil, fmt.Errorf("invalid URI: %s", uri)
		}
		switch strings.ToLower(u.Scheme) {
		case "https", "file":
			continue
		case "http":
			return nil, fmt.Errorf("insecure HTTP URL not allowed: %s (use HTTPS instead)", uri)
		default:
			return nil, fmt.Errorf("invalid URI scheme: %s (must use https or file)", uri)
		}
	}

	return uris, nil
}

// validateAndPrepareInputs validates options and prepares URLs and fingerprints.
func validateAndPrepareInputs(opts *AddOptions) (hashAlgo string, uris []string, fingerprints []string, err error) {
	if err := vendors.ValidateVendorID(opts.VendorID); err != nil {
		return "", nil, nil, err
	}

	if opts.Concurrency > concurrency.MaxWorkers {
		return "", nil, nil, fmt.Errorf("concurrency value %d exceeds maximum allowed (%d)", opts.Concurrency, concurrency.MaxWorkers)
	}

	// Parse and validate fingerprints
	fingerprints, inferredAlgo, err := parseAndValidateFingerprints(opts.Fingerprint)
	if err != nil {
		return "", nil, nil, err
	}

	// Determine hash algorithm
	hashAlgo, err = determineHashAlgorithm(inferredAlgo, opts.HashAlgorithm)
	if err != nil {
		return "", nil, nil, err
	}

	// Parse and validate URLs
	uris, err = parseAndValidateURIs(opts.URIs)
	if err != nil {
		return "", nil, nil, err
	}

	if len(fingerprints) > 0 && len(fingerprints) != len(uris) {
		return "", nil, nil, fmt.Errorf("number of fingerprints (%d) doesn't match number of URLs (%d)", len(fingerprints), len(uris))
	}

	// Warn if multiple URLs provided with -n flag
	if len(uris) > 1 && opts.Name != "" {
		cli.DisplayWarning("⚠️  Multiple URIs provided, ignoring -n flag (names will be deduced from certificate CN)")
	}

	return hashAlgo, uris, fingerprints, nil
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
	uri string
	err error
}

// processDownloadResults processes download results and creates certificate entries.
func processDownloadResults(results []certDownloadResult, existingCerts []config.Certificate, providedName, hashAlgo string, uriCount int) ([]config.Certificate, []downloadFailure) {
	var successfulCerts []config.Certificate
	var failures []downloadFailure

	for _, result := range results {
		if result.err != nil {
			failures = append(failures, downloadFailure{result.uri, result.err})
			continue
		}

		// Determine certificate name
		certName := providedName
		if certName == "" {
			certName = extractCertificateName(result.cert)
			if certName == "" {
				failures = append(failures, downloadFailure{result.uri, fmt.Errorf("certificate CN is empty, please provide a name with -n flag")})
				continue
			}
			if uriCount == 1 {
				cli.DisplayWarning("⚠️  No name provided, using certificate CN: %s", certName)
			}
		}

		if err := validate.CheckCertificate(existingCerts, result.uri, result.cert); err != nil {
			failures = append(failures, downloadFailure{result.uri, err})
			continue
		}

		fingerprintValidation := config.NewFingerprint(hashAlgo, result.fingerprint)
		newCert := config.Certificate{
			Name: certName,
			URI:  result.uri,
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
				fmt.Printf("  • %s - %v\n", f.uri, f.err)
			}
		}
	}

	if successCount == 0 {
		return fmt.Errorf("no certificates were added")
	}

	return nil
}

// downloadCertificatesParallel downloads multiple certificates in parallel with a goroutine limit.
func downloadCertificatesParallel(ctx context.Context, uris []string, fingerprints []string, hashAlgo string, maxWorkers int) []certDownloadResult {
	type downloadInput struct {
		uri         string
		fingerprint string
	}

	inputs := make([]downloadInput, len(uris))
	for i, uri := range uris {
		inputs[i] = downloadInput{uri: uri}
		if i < len(fingerprints) {
			inputs[i].fingerprint = fingerprints[i]
		}
	}

	return concurrency.Execute(maxWorkers, inputs, func(idx int, input downloadInput) certDownloadResult {
		result := certDownloadResult{uri: input.uri}

		// Download certificate
		client := download.NewClient()
		cert, err := client.FetchCertificate(ctx, input.uri)
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
			if len(uris) == 1 {
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
	hash := fingerprint.FormatFingerprint(parts[1])

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
