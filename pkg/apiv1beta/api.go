package apiv1beta

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
)

type VerifyResult = verifier.VerifyResult

var (
	mu         sync.RWMutex
	httpClient = http.DefaultClient // default HTTP client
)

const (
	bundleFilename = "tpm-ca-certificates.pem"
	checksumsFile  = "checksums.txt"
	checksumsSig   = "checksums.txt.sigstore.json"
)

var (
	// ErrBundleNotFound is returned when the requested bundle is not found.
	ErrBundleNotFound = errors.New("trusted bundle not found for the specified date")

	// ErrBundleVerificationFailed is returned when the bundle verification fails.
	ErrBundleVerificationFailed = errors.New("trusted bundle verification failed")
)

// HttpClient returns the current HTTP client used for requests.
func HttpClient() *http.Client {
	mu.RLock()
	defer mu.RUnlock()
	return httpClient
}

// SetHttpClient sets a custom HTTP client for requests.
func SetHttpClient(client *http.Client) {
	mu.Lock()
	defer mu.Unlock()
	httpClient = client
}

// GetConfig configures the bundle retrieval.
type GetConfig struct {
	// Date specifies the bundle release date in YYYY-MM-DD format.
	//
	// Optional. If empty, the latest release will be fetched.
	Date string

	// AutoUpdate configures automatic updates of the bundle.
	//
	// Optional. If not set, auto-update is enabled with a default interval of 24 hours.
	AutoUpdate AutoUpdateConfig

	// VendorIDs specifies the list of vendor IDs to filter when calling 'TrustedBundle.GetRoots()'.
	//
	// It can be helpful when your TPM chips comes from specific vendors and you want to adopt
	// a least-privilege approach.
	//
	// Optional. If empty, all vendors will be included.
	VendorIDs []VendorID

	// SkipVerify disables bundle verification.
	//
	// Optional. By default the bundle will be verified using Cosign and GitHub Attestations.
	SkipVerify bool

	// HTTPClient is the HTTP client to use for requests.
	//
	// Optional. If nil, [http.DefaultClient] will be used.
	HTTPClient *http.Client

	// sourceRepo is the GitHub repository to fetch bundles from.
	//
	// This field is internal for security reasons and should not be set by users.
	sourceRepo *github.Repo
}

// CheckAndSetDefaults validates and sets default values.
func (c *GetConfig) CheckAndSetDefaults() error {
	if c.sourceRepo == nil {
		c.sourceRepo = &github.Repo{
			Owner: github.SourceRepo.Owner,
			Name:  github.SourceRepo.Name,
		}
	}
	if err := c.sourceRepo.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid source repository: %w", err)
	}
	if c.HTTPClient == nil {
		c.HTTPClient = HttpClient()
	}
	if err := c.AutoUpdate.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid auto-update config: %w", err)
	}
	for _, vendorID := range c.VendorIDs {
		if err := vendorID.Validate(); err != nil {
			return fmt.Errorf("invalid vendor ID: %w", err)
		}
	}
	return nil
}

// getRawTrustedBundle retrieves and optionally verifies a TPM trust bundle from transparency
// log assets:
//   - integrity: checksums.txt and checksums.txt.sigstore.json (stored in GitHub Releases)
//   - provenance: GitHub Attestation (stored in GitHub API)
func getRawTrustedBundle(ctx context.Context, cfg GetConfig) ([]byte, error) {
	client := github.NewHTTPClient(cfg.HTTPClient)

	releaseTag, err := getReleaseTag(ctx, client, cfg)
	if err != nil {
		return nil, err
	}

	bundleData, err := client.DownloadAsset(ctx, *cfg.sourceRepo, releaseTag, bundleFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to download bundle: %w", err)
	}

	// Skip verification if requested
	if cfg.SkipVerify {
		return bundleData, nil
	}

	if _, err := VerifyTrustedBundle(ctx, VerifyConfig{
		Bundle:     bundleData,
		sourceRepo: cfg.sourceRepo,
		HTTPClient: cfg.HTTPClient,
	}); err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return bundleData, nil
}

// getReleaseTag determines which release to fetch.
func getReleaseTag(ctx context.Context, client *github.HTTPClient, cfg GetConfig) (string, error) {
	if cfg.Date != "" {
		if err := client.ReleaseExists(ctx, *cfg.sourceRepo, cfg.Date); err != nil {
			return "", fmt.Errorf("release %s not found: %w", cfg.Date, err)
		}
		return cfg.Date, nil
	}

	opts := github.ReleasesOptions{
		// safe page size to be sure to get at least one release 'YYYY-MM-DD'
		PageSize:         50,
		ReturnFirstValue: true,
		SortOrder:        github.SortOrderDesc,
	}
	releases, err := client.GetReleases(ctx, *cfg.sourceRepo, opts)
	if err != nil {
		return "", fmt.Errorf("failed to fetch releases: %w", err)
	}
	if len(releases) == 0 {
		return "", fmt.Errorf("no releases found")
	}
	return releases[0].TagName, nil
}

// VerifyConfig configures the bundle verification.
type VerifyConfig struct {
	// Bundle is the content of the trusted bundle to verify.
	//
	// Required.
	Bundle []byte

	// BundleMetadata is the metadata of the bundle to verify.
	//
	// Optional. If not provided, the metadata will be extracted from the bundle content.
	BundleMetadata *bundle.Metadata

	// Checksum is the content of the checksums.txt file to use for verification.
	//
	// Optional. If not provided, the checksum file will be downloaded from the release
	// matching the bundle date.
	Checksum []byte

	// ChecksumSignature is the content of the checksums.txt.sigstore.json file to use for verification.
	//
	// Optional. If not provided, the checksum signature file will be downloaded from the release
	// matching the bundle date.
	ChecksumSignature []byte

	// HTTPClient is the HTTP client to use for requests.
	//
	// Optional. If nil, http.DefaultClient will be used.
	HTTPClient *http.Client

	// sourceRepo is the GitHub repository to fetch bundles from.
	//
	// This field is internal for security reasons and should not be set by users.
	sourceRepo *github.Repo
}

// CheckAndSetDefaults validates and sets default values.
func (c *VerifyConfig) CheckAndSetDefaults() error {
	if len(c.Bundle) == 0 {
		return fmt.Errorf("bundle cannot be empty")
	}

	if c.BundleMetadata == nil {
		metadata, err := bundle.ParseMetadata(c.Bundle)
		if err != nil {
			return fmt.Errorf("failed to parse bundle metadata: %w", err)
		}
		c.BundleMetadata = metadata
	}

	if c.sourceRepo == nil {
		c.sourceRepo = &github.Repo{
			Owner: github.SourceRepo.Owner,
			Name:  github.SourceRepo.Name,
		}
	}
	if err := c.sourceRepo.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid source repository: %w", err)
	}
	if c.HTTPClient == nil {
		c.HTTPClient = HttpClient()
	}

	return nil
}

// VerifyTrustedBundle verifies the authenticity and integrity of a TPM trust bundle.
//
// The function performs cryptographic verification using both Cosign signatures
// and GitHub Attestations. It can optionally download missing verification artifacts
// (checksums and signatures) from GitHub releases.
//
// Example:
//
//	// Verify with auto-detected metadata and auto-downloaded checksums
//	err := apiv1beta.VerifyTrustedBundle(context.Background(), apiv1beta.VerifyConfig{
//	    Bundle: bundleData,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify with explicit metadata and checksums
//	err = apiv1beta.VerifyTrustedBundle(context.Background(), apiv1beta.VerifyConfig{
//	    Bundle:            bundleData,
//	    BundleMetadata:    &bundle.Metadata{Date: "2025-12-05", Commit: "abc123"},
//	    Checksum:          checksumData,
//	    ChecksumSignature: checksumSigData,
//	})
func VerifyTrustedBundle(ctx context.Context, cfg VerifyConfig) (*VerifyResult, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	client := github.NewHTTPClient(cfg.HTTPClient)

	effectiveChecksum := cfg.Checksum
	effectiveChecksumSig := cfg.ChecksumSignature

	assetCfg := assetConfig{
		client: client,
		repo:   *cfg.sourceRepo,
		date:   cfg.BundleMetadata.Date,
	}
	if len(effectiveChecksum) == 0 {
		var err error
		assetCfg.name = checksumsFile
		effectiveChecksum, err = getAsset(ctx, assetCfg)
		if err != nil {
			return nil, err
		}
	}
	if len(effectiveChecksumSig) == 0 {
		var err error
		assetCfg.name = checksumsSig
		effectiveChecksumSig, err = getAsset(ctx, assetCfg)
		if err != nil {
			return nil, err
		}
	}

	verifierCfg := verifier.Config{
		Date:             cfg.BundleMetadata.Date,
		Commit:           cfg.BundleMetadata.Commit,
		SourceRepo:       cfg.sourceRepo,
		WorkflowFilename: github.ReleaseBundleWorkflowPath,
		GitHubClient:     client,
	}

	v, err := verifier.New(verifierCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	bundleDigest := digest.ComputeSHA256(cfg.Bundle)
	result, err := v.Verify(ctx, cfg.Bundle, effectiveChecksum, effectiveChecksumSig, bundleDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundleVerificationFailed, err)
	}

	return result, nil
}

type assetConfig struct {
	client *github.HTTPClient
	repo   github.Repo
	name   string
	date   string
}

// getAsset downloads a specific asset from a GitHub release.
func getAsset(ctx context.Context, cfg assetConfig) ([]byte, error) {
	asset, err := cfg.client.DownloadAsset(ctx, cfg.repo, cfg.date, cfg.name)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", cfg.name, err)
	}
	return asset, nil
}

// GetTrustedBundle retrieves and parses a TPM trust bundle from GitHub releases.
//
// The function downloads the bundle, verifies it (unless SkipVerify is true),
// parses it into a certificate catalog organized by vendor, and returns a [TrustedBundle]
// interface that provides thread-safe access to the bundle data.
//
// If AutoUpdate is enabled, the bundle will automatically check for updates in the background
// and update itself when a newer version is available.
//
// Example:
//
//	// Get the latest verified bundle with all certificates
//	tb, err := apiv1beta.GetTrustedBundle(context.Background(), apiv1beta.GetConfig{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer tb.Stop()
//
//	certPool := tb.GetRoots()
//
//	// Get a specific date's bundle filtered by vendor
//	tb, err = apiv1beta.GetTrustedBundle(context.Background(), apiv1beta.GetConfig{
//	    Date:      "2025-12-03",
//	    VendorIDs: []apiv1beta.VendorID{apiv1beta.IFX, apiv1beta.NTC},
//	})
//
//	// Enable auto-update every 6 hours
//	tb, err = apiv1beta.GetTrustedBundle(context.Background(), apiv1beta.GetConfig{
//	    AutoUpdate: apiv1beta.AutoUpdateConfig{
//	        Interval: 6 * time.Hour,
//	    },
//	})
func GetTrustedBundle(ctx context.Context, cfg GetConfig) (TrustedBundle, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Fetch raw bundle data
	bundleData, err := getRawTrustedBundle(ctx, cfg)
	if err != nil {
		return nil, err
	}

	metadata, err := bundle.ParseMetadata(bundleData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bundle metadata: %w", err)
	}

	catalog, err := bundle.ParseBundle(bundleData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bundle: %w", err)
	}

	tb := &trustedBundle{
		raw:          bundleData,
		metadata:     metadata,
		catalog:      catalog,
		vendorFilter: cfg.VendorIDs,
	}

	// Start auto-update watcher if enabled
	if !cfg.AutoUpdate.DisableAutoUpdate {
		tb.startWatcher(ctx, cfg, cfg.AutoUpdate.Interval)
	}

	return tb, nil
}
