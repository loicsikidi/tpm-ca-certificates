package apiv1beta

import (
	"fmt"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

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
	HTTPClient utils.HTTPClient

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
		c.HTTPClient = HTTPClient()
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

func (c GetConfig) GetHTTPClient() utils.HTTPClient {
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
		cfg.needChecksums = true
		cfg.needChecksumSignature = true
		cfg.needProvenance = true
	}
	return cfg
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

	// CachePath is the location on disk for tpmtb cache.
	//
	// Optional. If empty, the default cache path is used ($HOME/.tpmtb).
	CachePath string

	// HTTPClient is the HTTP client to use for requests.
	//
	// Optional. If nil, http.DefaultClient will be used.
	HTTPClient utils.HTTPClient

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
		bundle:                c.Bundle,
		httpClient:            c.HTTPClient,
		cachePath:             c.CachePath,
		disableLocalCache:     c.DisableLocalCache,
		tag:                   c.BundleMetadata.Date,
		sourceRepo:            c.sourceRepo,
		needChecksums:         len(c.Checksum) == 0,
		needChecksumSignature: len(c.ChecksumSignature) == 0,
		needProvenance:        len(c.Provenance) == 0,
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
		c.HTTPClient = HTTPClient()
	}
	if c.CachePath == "" {
		c.CachePath = cache.CacheDir()
	}

	return nil
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
	HTTPClient utils.HTTPClient
}

// CheckAndSetDefaults validates and sets default values.
func (c *SaveConfig) CheckAndSetDefaults() error {
	if c.HTTPClient == nil {
		c.HTTPClient = HTTPClient()
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

// LoadConfig configures the bundle loading from disk.
type LoadConfig struct {
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

	// OfflineMode enables offline verification mode using assets stored in the cache directory.
	//
	// This mode automatically disables auto-update since the cached trusted-root.json may not work
	// with future bundles due to Sigstore key rotation.
	//
	// Optional. Default is false (online mode).
	OfflineMode bool
}

// CheckAndSetDefaults validates and sets default values.
func (c *LoadConfig) CheckAndSetDefaults() error {
	if c.CachePath == "" {
		c.CachePath = cache.CacheDir()
	}
	if !utils.DirExists(c.CachePath) {
		return fmt.Errorf("cache directory does not exist: %s", c.CachePath)
	}
	if c.OfflineMode && c.DisableLocalCache {
		return fmt.Errorf("offline mode requires local cache to be enabled")
	}
	return nil
}

func (c LoadConfig) GetHTTPClient() utils.HTTPClient {
	return nil
}

func (c LoadConfig) GetSkipVerify() bool {
	return c.SkipVerify
}

func (c LoadConfig) GetDisableLocalCache() bool {
	return c.DisableLocalCache
}

func (c LoadConfig) GetCachePath() string {
	return c.CachePath
}

// AutoUpdateConfig configures automatic updates of the bundle.
type AutoUpdateConfig struct {
	// DisableAutoUpdate disables automatic updates of the bundle.
	//
	// Optional. Default is false (auto-update enabled).
	DisableAutoUpdate bool `json:"disableAutoUpdate"`

	// Interval specifies how often the bundle should be updated.
	//
	// Optional. If zero, the default interval of 24 hours is used.
	Interval time.Duration `json:"interval"`
}

// CheckAndSetDefaults validates and sets default values.
func (c *AutoUpdateConfig) CheckAndSetDefaults() error {
	if c.Interval == 0 && !c.DisableAutoUpdate {
		c.Interval = 24 * time.Hour
	}
	return nil
}
