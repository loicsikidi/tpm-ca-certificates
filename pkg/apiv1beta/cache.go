package apiv1beta

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

const (
	CacheConfigFilename       = "config.json"
	CacheRootBundleFilename   = "tpm-ca-certificates.pem"
	CacheChecksumsFilename    = "checksums.txt"
	CacheChecksumsSigFilename = "checksums.txt.sigstore.json"
	CacheProvenanceFilename   = "roots.provenance.json"
)

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
	if err := c.AutoUpdate.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid auto-update config: %w", err)
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
	configPath := filepath.Join(cachePath, CacheConfigFilename)
	configData, err := os.ReadFile(configPath)
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
