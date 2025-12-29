package apiv1beta

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

// Aliases for backward compatibility - these constants are now defined in internal/cache
const (
	CacheConfigFilename             = cache.ConfigFilename
	CacheRootBundleFilename         = cache.RootBundleFilename
	CacheIntermediateBundleFilename = cache.IntermediateBundleFilename
	CacheChecksumsFilename          = cache.ChecksumsFilename
	CacheChecksumsSigFilename       = cache.ChecksumsSigFilename
	CacheProvenanceFilename         = cache.ProvenanceFilename
	CacheTrustedRootFilename        = cache.TrustedRootFilename
)

// CacheFilenames is the list of all expected cache files.
// This is an alias for backward compatibility.
var CacheFilenames = cache.Filenames

// CacheConfig represents the persisted configuration for a [TrustedBundle].
type CacheConfig struct {
	// Version is the bundle version (YYYY-MM-DD format).
	Version string `json:"version"`

	// AutoUpdate is the auto-update configuration.
	AutoUpdate *AutoUpdateConfig `json:"autoUpdate,omitempty"`

	// SkipVerify indicates whether bundle verification was skipped.
	SkipVerify bool `json:"skipVerify,omitempty"`

	// VendorIDs is the list of vendor IDs to filter.
	VendorIDs []VendorID `json:"vendorIDs,omitempty"`

	// LastTimestamp is the timestamp of the last update.
	LastTimestamp time.Time `json:"lastTimestamp"`
}

// CheckAndSetDefaults validates and sets default values.
func (c *CacheConfig) CheckAndSetDefaults() error {
	if c.Version == "" {
		return fmt.Errorf("version cannot be empty")
	}
	if c.AutoUpdate != nil {
		if err := c.AutoUpdate.CheckAndSetDefaults(); err != nil {
			return fmt.Errorf("invalid auto-update config: %w", err)
		}
	}
	for _, vendorID := range c.VendorIDs {
		if err := vendorID.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// checkCacheExists verifies if a cache exists for the specified version.
func checkCacheExists(cachePath string, version string) bool {
	configData, err := cache.LoadFile(cachePath, cache.ConfigFilename)
	if err != nil {
		return false
	}

	var cfg CacheConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return false
	}

	if cfg.Version != version {
		return false
	}

	if !utils.FileExists(filepath.Join(cachePath, CacheRootBundleFilename)) {
		return false
	}

	if !cfg.SkipVerify {
		if !utils.FileExists(filepath.Join(cachePath, CacheProvenanceFilename)) ||
			!utils.FileExists(filepath.Join(cachePath, CacheChecksumsFilename)) ||
			!utils.FileExists(filepath.Join(cachePath, CacheChecksumsSigFilename)) {
			return false
		}
	}

	return true
}

// persistAllBundleAssets writes all bundle assets including intermediate bundle, trusted root, and cache config
// to the specified output directory.
//
// This is a shared helper used by both [SaveResponse.Persist] and [trustedBundle.Persist] to avoid code duplication.
func persistAllBundleAssets(
	outputDir string,
	rootBundle []byte,
	intermediateBundle []byte,
	checksum []byte,
	checksumSignature []byte,
	provenance []byte,
	trustedRoot []byte,
	cacheConfig []byte,
) error {
	// Save core bundle assets
	if err := cache.SaveFile(outputDir, cache.RootBundleFilename, rootBundle); err != nil {
		return err
	}
	if err := cache.SaveFile(outputDir, cache.ChecksumsFilename, checksum); err != nil {
		return err
	}
	if err := cache.SaveFile(outputDir, cache.ChecksumsSigFilename, checksumSignature); err != nil {
		return err
	}
	if err := cache.SaveFile(outputDir, cache.ProvenanceFilename, provenance); err != nil {
		return err
	}
	if err := cache.SaveFile(outputDir, cache.ConfigFilename, cacheConfig); err != nil {
		return err
	}

	// Save intermediate bundle if present
	if len(intermediateBundle) > 0 {
		if err := cache.SaveFile(outputDir, cache.IntermediateBundleFilename, intermediateBundle); err != nil {
			return err
		}
	}

	// Save trusted root if present
	if len(trustedRoot) > 0 {
		if err := cache.SaveFile(outputDir, cache.TrustedRootFilename, trustedRoot); err != nil {
			return err
		}
	}

	return nil
}
