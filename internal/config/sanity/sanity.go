package sanity

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/concurrency"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/download"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/validate"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

// ValidationError represents a certificate validation error.
type ValidationError struct {
	VendorID   string
	VendorName string
	CertName   string
	Error      error
}

func (e ValidationError) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  Vendor: %s (%s)\n", e.VendorName, e.VendorID))
	b.WriteString(fmt.Sprintf("  Certificate: %s\n", e.CertName))
	b.WriteString(fmt.Sprintf("  Error: %s\n", e.Error))
	return b.String()
}

// ExpirationWarning represents a certificate expiration warning.
type ExpirationWarning struct {
	VendorID   string
	VendorName string
	CertName   string
	DaysLeft   int
	IsExpired  bool
	ExpiryDate time.Time
}

func (w ExpirationWarning) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  Vendor: %s (%s)\n", w.VendorName, w.VendorID))
	b.WriteString(fmt.Sprintf("  Certificate: %s\n", w.CertName))
	if w.IsExpired {
		b.WriteString(fmt.Sprintf("  Status: Expired on %s\n", w.ExpiryDate.Format("2006-01-02")))
	} else {
		b.WriteString(fmt.Sprintf("  Status: Expires in %d days (%s)\n", w.DaysLeft, w.ExpiryDate.Format("2006-01-02")))
	}
	return b.String()
}

// Result contains the results of a sanity check.
type Result struct {
	ValidationErrors   []ValidationError
	ExpirationWarnings []ExpirationWarning
}

// HasIssues returns true if there are any validation errors or expiration warnings.
func (r *Result) HasIssues() bool {
	return len(r.ValidationErrors) > 0 || len(r.ExpirationWarnings) > 0
}

// Checker performs sanity checks on TPM certificates.
type Checker struct {
	downloader *download.Client
}

// NewChecker creates a new sanity checker.
func NewChecker() *Checker {
	return &Checker{
		downloader: download.NewClient(),
	}
}

// NewCheckerWithClient creates a new sanity checker with a custom HTTP client.
func NewCheckerWithClient(client utils.HttpClient) *Checker {
	return &Checker{
		downloader: download.NewClient(client),
	}
}

// Check performs sanity checks on all certificates in the configuration.
//
// It validates fingerprints and checks for certificate expiration.
// The process runs concurrently using the specified number of workers.
// If workers is 0, it auto-detects the optimal count.
func (c *Checker) Check(cfg *config.TPMRootsConfig, workers int, thresholdDays int) (*Result, error) {
	if workers == 0 {
		workers = concurrency.DetectCPUCount()
	}
	if workers > concurrency.MaxWorkers {
		workers = concurrency.MaxWorkers
	}
	if workers < 1 {
		workers = 1
	}

	type certCheck struct {
		vendorIdx int
		certIdx   int
		valErr    *ValidationError
		expWarn   *ExpirationWarning
		err       error
	}

	// Create a channel to limit concurrent vendor processing
	vendorChan := make(chan int, workers)
	resultsChan := make(chan certCheck, cfg.TotalCertificates())
	var wg sync.WaitGroup

	// Process each vendor concurrently
	for vendorIdx, vendor := range cfg.Vendors {
		wg.Add(1)
		go func(vIdx int, v config.Vendor) {
			defer wg.Done()

			// Acquire worker slot
			vendorChan <- 1
			defer func() { <-vendorChan }()

			// Process certificates for this vendor sequentially
			for certIdx, cert := range v.Certificates {
				valErr, expWarn, err := c.checkCertificate(cert, v.ID, v.Name, thresholdDays)
				resultsChan <- certCheck{
					vendorIdx: vIdx,
					certIdx:   certIdx,
					valErr:    valErr,
					expWarn:   expWarn,
					err:       err,
				}
			}
		}(vendorIdx, vendor)
	}

	// Close results channel when all workers are done
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	result := &Result{
		ValidationErrors:   make([]ValidationError, 0),
		ExpirationWarnings: make([]ExpirationWarning, 0),
	}

	for check := range resultsChan {
		if check.err != nil {
			return nil, check.err
		}
		if check.valErr != nil {
			result.ValidationErrors = append(result.ValidationErrors, *check.valErr)
		}
		if check.expWarn != nil {
			result.ExpirationWarnings = append(result.ExpirationWarnings, *check.expWarn)
		}
	}

	return result, nil
}

// checkCertificate validates a single certificate and checks its expiration.
func (c *Checker) checkCertificate(cert config.Certificate, vendorID, vendorName string, thresholdDays int) (*ValidationError, *ExpirationWarning, error) {
	x509Cert, err := c.downloader.DownloadCertificate(cert.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download certificate %q from vendor %q: %w", cert.Name, vendorName, err)
	}

	// Check fingerprint
	var valErr *ValidationError
	if err := validate.ValidateFingerprint(x509Cert, cert.Validation.Fingerprint); err != nil {
		valErr = &ValidationError{
			VendorID:   vendorID,
			VendorName: vendorName,
			CertName:   cert.Name,
			Error:      err,
		}
	}

	// Check expiration
	var expWarn *ExpirationWarning
	now := time.Now()
	daysUntilExpiry := int(x509Cert.NotAfter.Sub(now).Hours() / 24)

	if daysUntilExpiry < thresholdDays {
		expWarn = &ExpirationWarning{
			VendorID:   vendorID,
			VendorName: vendorName,
			CertName:   cert.Name,
			DaysLeft:   daysUntilExpiry,
			IsExpired:  daysUntilExpiry < 0,
			ExpiryDate: x509Cert.NotAfter,
		}
	}

	return valErr, expWarn, nil
}
