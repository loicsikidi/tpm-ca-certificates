package apiv1beta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	verifierutils "github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

type VerifyResult = verifier.VerifyResult

var (
	mu         sync.RWMutex
	httpClient = http.DefaultClient // default HTTP client
)

const (
	bundleFilename             = cache.RootBundleFilename
	intermediateBundleFilename = cache.IntermediateBundleFilename
	checksumsFile              = cache.ChecksumsFilename
	checksumsSig               = cache.ChecksumsSigFilename
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
		// Verify root bundle
		if _, err := VerifyTrustedBundle(ctx, VerifyConfig{
			Bundle:            assets.rootBundleData,
			Checksum:          assets.checksum,
			ChecksumSignature: assets.checksumSignature,
			Provenance:        assets.provenance,
			sourceRepo:        cfg.sourceRepo,
			HTTPClient:        cfg.HTTPClient,
			DisableLocalCache: cfg.DisableLocalCache,
		}); err != nil {
			return nil, fmt.Errorf("root bundle verification failed: %w", err)
		}

		// Verify intermediate bundle if present
		if len(assets.intermediateBundleData) > 0 {
			if _, err := VerifyTrustedBundle(ctx, VerifyConfig{
				Bundle:            assets.intermediateBundleData,
				Checksum:          assets.checksum,
				ChecksumSignature: assets.checksumSignature,
				Provenance:        assets.provenance,
				sourceRepo:        cfg.sourceRepo,
				HTTPClient:        cfg.HTTPClient,
				DisableLocalCache: cfg.DisableLocalCache,
			}); err != nil {
				return nil, fmt.Errorf("intermediate bundle verification failed: %w", err)
			}
		}
	}

	tb, err := newTrustedBundle(assets.rootBundleData, assets.intermediateBundleData)
	if err != nil {
		return nil, err
	}

	// Cache additional config to the trusted bundle
	tbImpl := tb.(*trustedBundle)
	tbImpl.disableLocalCache = cfg.DisableLocalCache
	tbImpl.vendorFilter = cfg.VendorIDs
	tbImpl.autoUpdateCfg = &cfg.AutoUpdate
	tbImpl.assets = assets

	// Parse intermediate bundle metadata if present
	if len(assets.intermediateBundleData) > 0 {
		intermediateMetadata, err := bundle.ParseMetadata(assets.intermediateBundleData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse intermediate bundle metadata: %w", err)
		}
		tbImpl.intermediateMetadata = intermediateMetadata
	}

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

	// TrustedRoot is the content of the trusted-root.json file to use for offline verification.
	// When provided, this Sigstore trusted root will be used instead of fetching from TUF.
	//
	// The trusted root must contain valid Sigstore public good certificates. Invalid or
	// untrusted certificates will cause verification to fail.
	//
	// Optional. If not provided, the trusted root will be fetched from Sigstore's TUF repository.
	TrustedRoot []byte

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
		TrustedRoot:       cfg.TrustedRoot,
	}

	v, err := verifier.New(verifierCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	verifyCfg := verifier.VerifyConfig{
		BundleData:       cfg.Bundle,
		ChecksumsData:    cfg.Checksum,
		ChecksumsSigData: cfg.ChecksumSignature,
		ProvenanceData:   cfg.Provenance,
	}

	result, err := v.Verify(ctx, verifyCfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundleVerificationFailed, err)
	}

	return result, nil
}

// SaveConfig configures the bundle saving for offline verification.
type SaveConfig struct {
	// Date specifies the bundle release date in YYYY-MM-DD format.
	//
	// Optional. If empty, the latest release will be fetched.
	Date string

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

	// HTTPClient is the HTTP client to use for requests.
	//
	// Optional. If nil, [http.DefaultClient] will be used.
	HTTPClient utils.HttpClient
}

// CheckAndSetDefaults validates and sets default values.
func (c *SaveConfig) CheckAndSetDefaults() error {
	if c.HTTPClient == nil {
		c.HTTPClient = HttpClient()
	}
	if c.CachePath == "" {
		c.CachePath = cache.CacheDir()
	}
	for _, vendorID := range c.VendorIDs {
		if err := vendorID.Validate(); err != nil {
			return fmt.Errorf("invalid vendor ID: %w", err)
		}
	}
	return nil
}

// SaveResponse contains all assets required for offline verification of a TPM bundle.
type SaveResponse struct {
	// RootBundle is the TPM root CA certificates bundle (PEM format).
	RootBundle []byte

	// Provenance is the GitHub Attestation provenance for produced bundle.
	Provenance []byte

	// IntermediateBundle is the TPM intermediate CA certificates bundle (PEM format).
	//
	// This field will be empty if the release does not contain an intermediate bundle.
	IntermediateBundle []byte

	// Checksum is the checksums.txt file content.
	Checksum []byte

	// ChecksumSignature is the checksums.txt.sigstore.json file content.
	ChecksumSignature []byte

	// TrustedRoot is the Sigstore trusted_root.json from TUF.
	TrustedRoot []byte

	// CacheConfig is the cache configuration (JSON format) containing metadata about the bundle.
	CacheConfig []byte
}

// Persist writes all assets to the specified output directory.
//
// If outputDir is empty, the default cache directory ($HOME/.tpmtb) is used.
func (sr *SaveResponse) Persist(outputDir string) error {
	if outputDir == "" {
		outputDir = cache.CacheDir()
	}

	outputDir = filepath.Clean(outputDir)

	if !utils.DirExists(outputDir) {
		if err := os.MkdirAll(outputDir, 0700); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	return persistAllBundleAssets(
		outputDir,
		sr.RootBundle,
		sr.IntermediateBundle,
		sr.Checksum,
		sr.ChecksumSignature,
		sr.Provenance,
		sr.TrustedRoot,
		sr.CacheConfig,
	)
}

// Save retrieves a TPM trust bundle and all verification assets required for offline verification.
//
// This function downloads the bundle, verifies it, fetches the TUF trust chains from Rekor,
// and returns a [SaveResponse] containing all necessary files for offline verification.
//
// The returned [SaveResponse] can be persisted to disk using the Persist method, which will
// save all assets to the local cache directory ($HOME/.tpmtb by default).
//
// Example:
//
//	// Save the latest bundle with all verification assets
//	resp, err := apiv1beta.Save(context.Background(), apiv1beta.SaveConfig{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Persist to default cache directory ($HOME/.tpmtb)
//	if err := resp.Persist(); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Save a specific date's bundle filtered by vendor
//	resp, err = apiv1beta.Save(context.Background(), apiv1beta.SaveConfig{
//	    Date:      "2025-12-05",
//	    VendorIDs: []apiv1beta.VendorID{apiv1beta.IFX, apiv1beta.NTC},
//	})
func Save(ctx context.Context, cfg SaveConfig) (*SaveResponse, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Use GetTrustedBundle to fetch and verify the bundle
	// This gives us all the assets and handles verification automatically
	tb, err := GetTrustedBundle(ctx, GetConfig{
		Date:       cfg.Date,
		CachePath:  cfg.CachePath,
		VendorIDs:  cfg.VendorIDs,
		HTTPClient: cfg.HTTPClient,
		AutoUpdate: AutoUpdateConfig{
			DisableAutoUpdate: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted bundle: %w", err)
	}

	// Fetch the Sigstore trusted_root.json from TUF
	trustedRoot, err := verifierutils.FetchTrustedRoot(cfg.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch trusted root: %w", err)
	}

	// Extract assets from the trusted bundle
	tbImpl := tb.(*trustedBundle)
	assets := tbImpl.assets
	metadata := tbImpl.rootMetadata

	// Build cache config
	cacheCfg := CacheConfig{
		Version:       metadata.Date,
		VendorIDs:     cfg.VendorIDs,
		AutoUpdate:    &AutoUpdateConfig{DisableAutoUpdate: true},
		SkipVerify:    false,
		LastTimestamp: time.Now(),
	}

	cacheConfigData, err := json.Marshal(cacheCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cache config: %w", err)
	}

	return &SaveResponse{
		RootBundle:         assets.rootBundleData,
		Provenance:         assets.provenance,
		IntermediateBundle: assets.intermediateBundleData,
		Checksum:           assets.checksum,
		ChecksumSignature:  assets.checksumSignature,
		TrustedRoot:        trustedRoot,
		CacheConfig:        cacheConfigData,
	}, nil
}
