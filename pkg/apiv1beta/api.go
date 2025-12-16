package apiv1beta

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
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

	// ErrCannotPersistTrustedBundle is returned when the bundle cannot be persisted due to disabled local cache.
	ErrCannotPersistTrustedBundle = errors.New("local cache is disabled; cannot persist bundle")
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

	// CachePath is the location on disk for tpmtb cache.
	//
	// Optional. If empty, the default cache path is used ($HOME/.tpmtb).
	CachePath string

	// DisableLocalCache mode allows to work on a read-only
	// files system if this is set, cache path is ignored.
	//
	// Optional. Default is false (local cache enabled).
	DisableLocalCache bool

	// SkipVerify disables bundle verification.
	//
	// Optional. By default the bundle will be verified using Cosign and GitHub Attestations.
	SkipVerify bool

	// HTTPClient is the HTTP client to use for requests.
	//
	// Optional. If nil, [http.DefaultClient] will be used.
	HTTPClient utils.HttpClient

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
	if c.CachePath == "" {
		c.CachePath = cache.CacheDir()
	}
	return nil
}

func (c GetConfig) GetHttpClient() utils.HttpClient {
	return c.HTTPClient
}

func (c GetConfig) GetSkipVerify() bool {
	return c.SkipVerify
}

func (c GetConfig) GetDisableLocalCache() bool {
	return c.DisableLocalCache
}

func (c GetConfig) GetCachePath() string {
	return c.CachePath
}

func (c *GetConfig) toAssetsConfig() assetsConfig {
	cfg := assetsConfig{
		httpClient:        c.HTTPClient,
		cachePath:         c.CachePath,
		disableLocalCache: c.DisableLocalCache,
		sourceRepo:        c.sourceRepo,
	}
	if !c.SkipVerify {
		cfg.downloadChecksums = true
		cfg.downloadChecksumSignature = true
		cfg.downloadProvenance = true
	}
	return cfg
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

	releaseTag, err := getReleaseTag(ctx, cfg)
	if err != nil {
		return nil, err
	}

	assetsCfg := cfg.toAssetsConfig()
	assetsCfg.tag = releaseTag
	assets, err := getAssets(ctx, assetsCfg)
	if err != nil {
		return nil, err
	}

	if !cfg.SkipVerify {
		if _, err := VerifyTrustedBundle(ctx, VerifyConfig{
			Bundle:            assets.bundleData,
			Checksum:          assets.checksum,
			ChecksumSignature: assets.checksumSignature,
			Provenance:        assets.provenance,
			sourceRepo:        cfg.sourceRepo,
			HTTPClient:        cfg.HTTPClient,
			DisableLocalCache: cfg.DisableLocalCache,
		}); err != nil {
			return nil, fmt.Errorf("verification failed: %w", err)
		}
	}

	tb, err := newTrustedBundle(assets.bundleData)
	if err != nil {
		return nil, err
	}

	// Cache additional config to the trusted bundle
	tbImpl := tb.(*trustedBundle)
	tbImpl.disableLocalCache = cfg.DisableLocalCache
	tbImpl.vendorFilter = cfg.VendorIDs
	tbImpl.autoUpdateCfg = &cfg.AutoUpdate
	tbImpl.assets = assets

	if !cfg.DisableLocalCache {
		// Persist only if not already cached
		if !checkCacheExists(cfg.CachePath, releaseTag) {
			if err := tbImpl.Persist(cfg.CachePath); err != nil {
				return nil, fmt.Errorf("failed to persist bundle to cache (if running on read-only filesystem, set DisableLocalCache=true): %w", err)
			}
		}
	}

	if !cfg.AutoUpdate.DisableAutoUpdate {
		tbImpl.startWatcher(ctx, cfg, cfg.AutoUpdate.Interval)
	}

	return tb, nil
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

	// Provenance is the content the build attestation provenance bound to the bundle to use for verification.
	//
	// Optional. If not provided, the provenance will be downloaded from the GitHub API.
	Provenance []byte

	// HTTPClient is the HTTP client to use for requests.
	//
	// Optional. If nil, http.DefaultClient will be used.
	HTTPClient utils.HttpClient

	// DisableLocalCache mode allows to work on a read-only
	// files system if this is set, cache path is ignored.
	//
	// Optional. Default is false (local cache enabled).
	DisableLocalCache bool

	// sourceRepo is the GitHub repository to fetch bundles from.
	//
	// This field is internal for security reasons and should not be set by users.
	sourceRepo *github.Repo
}

func (c *VerifyConfig) shouldFetchVerificationAssets() bool {
	return len(c.Checksum) == 0 || len(c.ChecksumSignature) == 0 || len(c.Provenance) == 0
}

func (c *VerifyConfig) toAssetsConfig() assetsConfig {
	return assetsConfig{
		bundle:                    c.Bundle,
		httpClient:                c.HTTPClient,
		cachePath:                 cache.CacheDir(),
		disableLocalCache:         c.DisableLocalCache,
		tag:                       c.BundleMetadata.Date,
		sourceRepo:                c.sourceRepo,
		downloadChecksums:         len(c.Checksum) == 0,
		downloadChecksumSignature: len(c.ChecksumSignature) == 0,
		downloadProvenance:        len(c.Provenance) == 0,
	}
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
	if err := c.BundleMetadata.Check(); err != nil {
		return fmt.Errorf("invalid bundle metadata: %w", err)
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

	if cfg.shouldFetchVerificationAssets() {
		assets, err := getAssets(ctx, cfg.toAssetsConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to download verification assets: %w", err)
		}
		if len(cfg.Checksum) == 0 {
			cfg.Checksum = assets.checksum
		}
		if len(cfg.ChecksumSignature) == 0 {
			cfg.ChecksumSignature = assets.checksumSignature
		}
		if len(cfg.Provenance) == 0 {
			cfg.Provenance = assets.provenance
		}
	}

	verifierCfg := verifier.Config{
		Date:              cfg.BundleMetadata.Date,
		Commit:            cfg.BundleMetadata.Commit,
		SourceRepo:        cfg.sourceRepo,
		WorkflowFilename:  github.ReleaseBundleWorkflowPath,
		HTTPClient:        cfg.HTTPClient,
		DisableLocalCache: cfg.DisableLocalCache,
	}

	v, err := verifier.New(verifierCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	bundleDigest := digest.ComputeSHA256(cfg.Bundle)
	result, err := v.Verify(ctx, cfg.Bundle, cfg.Checksum, cfg.ChecksumSignature, cfg.Provenance, bundleDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundleVerificationFailed, err)
	}

	return result, nil
}
