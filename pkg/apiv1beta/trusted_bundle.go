package apiv1beta

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/vendors"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

const (
	CacheConfigFilename       = "config.json"
	CacheRootBundleFilename   = "tpm-ca-certificates.pem"
	CacheChecksumsFilename    = "checksums.txt"
	CacheChecksumsSigFilename = "checksums.txt.sigstore.json"
	CacheProvenanceFilename   = "roots.provenance.json"
)

// TrustedBundle represents a TPM trust bundle with certificate catalog organized by vendor.
//
// All methods are thread-safe and can be called concurrently.
//
// Example:
//
//	tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer tb.Stop()
//
//	certPool := tb.GetRoots()
//	metadata := tb.GetMetadata()
type TrustedBundle interface {
	// GetRaw returns the raw PEM-encoded bundle.
	GetRaw() []byte

	// GetMetadata returns the bundle metadata (date and commit).
	GetMetadata() *bundle.Metadata

	// GetVendors returns the list of vendor IDs in the bundle.
	GetVendors() []VendorID

	// GetRoots returns an [x509.CertPool] containing all certificates from the bundle,
	// or only certificates from specified vendors if the bundle was created with VendorIDs filter.
	GetRoots() *x509.CertPool

	// Persist marshals bundle and its verification assets to disk at the specified cache path.
	//
	// Notes:
	//  * variadic cachePath argument is optional. If not provided, the default cache path is used.
	//  * if the files already exist, they will be overwritten.
	//  * use [Load] to reconstruct [TrustedBundle] from persisted files.
	Persist(cachePath ...string) error

	// Stop stops the auto-update watcher if enabled.
	//
	// This method blocks until the watcher is fully stopped or the timeout (5 seconds) is reached.
	// It is safe to call Stop multiple times.
	Stop() error
}

// trustedBundle is the internal implementation of [TrustedBundle].
type trustedBundle struct {
	mu       sync.RWMutex
	raw      []byte
	metadata *bundle.Metadata
	catalog  map[vendors.ID][]*x509.Certificate

	// vendorFilter is the list of vendors to filter when calling GetRoots.
	// If empty, all certificates are returned.
	vendorFilter []VendorID

	// Verification assets
	checksum          []byte
	checksumSignature []byte
	provenance        []byte

	autoUpdateCfg     *AutoUpdateConfig
	disableLocalCache bool

	// Auto-update fields
	stopChan    chan struct{}
	stoppedChan chan struct{}
	stopOnce    sync.Once
}

// GetRaw returns the raw PEM-encoded bundle.
func (tb *trustedBundle) GetRaw() []byte {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	// Return a copy to prevent external modifications
	return slices.Clone(tb.raw)
}

// GetMetadata returns the bundle metadata.
func (tb *trustedBundle) GetMetadata() *bundle.Metadata {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	// Return a copy to prevent external modifications
	metadata := *tb.metadata
	return &metadata
}

// GetVendors returns the list of vendor IDs in the bundle.
//
// If the bundle was created with VendorIDs filter, only those vendors (with at least
// one certificate in the bundle) are included.
func (tb *trustedBundle) GetVendors() []VendorID {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	if len(tb.vendorFilter) > 0 {
		vendors := make([]VendorID, 0, len(tb.vendorFilter))
		for _, vendorID := range tb.vendorFilter {
			if _, ok := tb.catalog[vendorID]; ok {
				vendors = append(vendors, vendorID)
			}
		}
		return vendors
	}

	vendors := make([]VendorID, 0, len(tb.catalog))
	for vendorID := range tb.catalog {
		vendors = append(vendors, vendorID)
	}
	return vendors
}

// GetRoots returns an x509.CertPool containing certificates.
//
// If the bundle was created with VendorIDs filter, only certificates from those vendors are included.
// Otherwise, all certificates from the bundle are included.
func (tb *trustedBundle) GetRoots() *x509.CertPool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	pool := x509.NewCertPool()

	// If no vendor filter, add all certificates
	if len(tb.vendorFilter) == 0 {
		for _, certs := range tb.catalog {
			for _, cert := range certs {
				pool.AddCert(cert)
			}
		}
		return pool
	}

	// Add only certificates from specified vendors
	for _, vendorID := range tb.vendorFilter {
		if certs, ok := tb.catalog[vendorID]; ok {
			for _, cert := range certs {
				pool.AddCert(cert)
			}
		}
	}

	return pool
}

// Persist writes the bundle and its configuration to disk.
func (tb *trustedBundle) Persist(cachePaths ...string) error {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	if tb.disableLocalCache {
		return ErrCannotPersistTrustedBundle
	}

	cachePath, err := utils.OptionalArg(cachePaths)
	if err != nil {
		cachePath = cache.CacheDir()
	}

	// sanitize cache path
	cachePath = filepath.Clean(cachePath)

	if !utils.DirExists(cachePath) {
		if err := os.MkdirAll(cachePath, 0755); err != nil {
			return fmt.Errorf("failed to create cache directory: %w", err)
		}
	}

	bundlePath := filepath.Join(cachePath, CacheRootBundleFilename)
	if err := os.WriteFile(bundlePath, tb.raw, 0644); err != nil {
		return fmt.Errorf("failed to write bundle: %w", err)
	}

	checksumsPath := filepath.Join(cachePath, CacheChecksumsFilename)
	if err := os.WriteFile(checksumsPath, tb.checksum, 0644); err != nil {
		return fmt.Errorf("failed to write checksums: %w", err)
	}

	checksumsSigPath := filepath.Join(cachePath, CacheChecksumsSigFilename)
	if err := os.WriteFile(checksumsSigPath, tb.checksumSignature, 0644); err != nil {
		return fmt.Errorf("failed to write checksum signature: %w", err)
	}

	provenancePath := filepath.Join(cachePath, CacheProvenanceFilename)
	if err := os.WriteFile(provenancePath, tb.provenance, 0644); err != nil {
		return fmt.Errorf("failed to write provenance: %w", err)
	}

	cfg := CacheConfig{
		AutoUpdate:    tb.autoUpdateCfg,
		VendorIDs:     tb.vendorFilter,
		LastTimestamp: time.Now(),
	}

	configData, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	configPath := filepath.Join(cachePath, CacheConfigFilename)
	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// Stop stops the auto-update watcher.
func (tb *trustedBundle) Stop() error {
	// If no auto-update was configured, nothing to stop
	if tb.stopChan == nil {
		return nil
	}

	tb.stopOnce.Do(func() {
		close(tb.stopChan)
	})

	// Wait for watcher to stop with timeout
	select {
	case <-tb.stoppedChan:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for auto-update watcher to stop")
	}
}

// update atomically updates the bundle data.
func (tb *trustedBundle) update(raw []byte, metadata *bundle.Metadata, catalog map[vendors.ID][]*x509.Certificate) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.raw = raw
	tb.metadata = metadata
	tb.catalog = catalog
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

// CacheConfig represents the persisted configuration for a [TrustedBundle].
type CacheConfig struct {
	// AutoUpdate is the auto-update configuration.
	AutoUpdate *AutoUpdateConfig `json:"autoUpdate,omitempty"`

	// VendorIDs is the list of vendor IDs to filter.
	VendorIDs []VendorID `json:"vendorIDs,omitempty"`

	// LastTimestamp is the timestamp of the last update.
	LastTimestamp time.Time `json:"lastTimestamp"`
}

// CheckAndSetDefaults validates and sets default values.
func (c *CacheConfig) CheckAndSetDefaults() error {
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
}

// CheckAndSetDefaults validates and sets default values.
func (c *LoadConfig) CheckAndSetDefaults() error {
	if c.CachePath == "" {
		c.CachePath = cache.CacheDir()
	}
	if !utils.DirExists(c.CachePath) {
		return fmt.Errorf("cache directory does not exist: %s", c.CachePath)
	}
	return nil
}

func (c LoadConfig) GetHttpClient() *http.Client {
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

// Load reads a persisted [TrustedBundle] from disk and verifies its integrity.
//
// Example:
//
//	tb, err := apiv1beta.Load(context.Background(), apiv1beta.LoadConfig{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer tb.Stop()
func Load(ctx context.Context, cfg LoadConfig) (TrustedBundle, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, err
	}

	bundlePath := filepath.Join(cfg.CachePath, CacheRootBundleFilename)
	bundleData, err := utils.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle: %w", err)
	}

	configPath := filepath.Join(cfg.CachePath, CacheConfigFilename)
	configData, err := utils.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cacheCfg CacheConfig
	if err := json.Unmarshal(configData, &cacheCfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cacheCfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	var checksumData, checksumSigData, provenanceData []byte
	if !cfg.SkipVerify {
		var err error
		checksumsPath := filepath.Join(cfg.CachePath, CacheChecksumsFilename)
		checksumData, err = utils.ReadFile(checksumsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read checksums: %w", err)
		}

		checksumsSigPath := filepath.Join(cfg.CachePath, CacheChecksumsSigFilename)
		checksumSigData, err = utils.ReadFile(checksumsSigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read checksum signature: %w", err)
		}

		provenancePath := filepath.Join(cfg.CachePath, CacheProvenanceFilename)
		provenanceData, err = utils.ReadFile(provenancePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read provenance: %w", err)
		}

		if _, err := VerifyTrustedBundle(ctx, VerifyConfig{
			Bundle:            bundleData,
			Checksum:          checksumData,
			ChecksumSignature: checksumSigData,
			Provenance:        provenanceData,
			DisableLocalCache: cfg.DisableLocalCache,
		}); err != nil {
			return nil, fmt.Errorf("verification failed: %w", err)
		}
	}

	// Create TrustedBundle from the loaded data
	tb, err := newTrustedBundle(bundleData)
	if err != nil {
		return nil, err
	}

	// Store vendor filter and verification assets
	tbImpl := tb.(*trustedBundle)
	tbImpl.vendorFilter = cacheCfg.VendorIDs
	tbImpl.checksum = checksumData
	tbImpl.checksumSignature = checksumSigData
	tbImpl.provenance = provenanceData

	if !cacheCfg.AutoUpdate.DisableAutoUpdate {
		tb.(*trustedBundle).startWatcher(ctx, cfg, cacheCfg.AutoUpdate.Interval)
	}

	return tb, nil
}

type updaterConfig interface {
	GetHttpClient() *http.Client
	GetSkipVerify() bool
	GetDisableLocalCache() bool
	GetCachePath() string
}

// startWatcher starts the auto-update watcher in a background goroutine.
func (tb *trustedBundle) startWatcher(ctx context.Context, cfg updaterConfig, interval time.Duration) {
	tb.stopChan = make(chan struct{})
	tb.stoppedChan = make(chan struct{})

	go func() {
		defer close(tb.stoppedChan)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-tb.stopChan:
				return
			case <-ticker.C:
				tb.checkAndUpdate(ctx, cfg)
			}
		}
	}()
}

// checkAndUpdate checks for a new bundle version and updates if necessary.
func (tb *trustedBundle) checkAndUpdate(ctx context.Context, cfg updaterConfig) {
	// Fetch the latest bundle without starting a watcher
	newBundle, err := GetTrustedBundle(ctx, GetConfig{
		Date:       "", // Always fetch latest
		SkipVerify: cfg.GetSkipVerify(),
		HTTPClient: cfg.GetHttpClient(),
		AutoUpdate: AutoUpdateConfig{
			DisableAutoUpdate: true, // Don't start a watcher for this temporary bundle
		},
	})
	if err != nil {
		// Silently fail and keep current bundle
		return
	}

	// Check if the date is newer
	currentMetadata := tb.GetMetadata()
	newMetadata := newBundle.GetMetadata()
	if newMetadata.Date <= currentMetadata.Date {
		// No update needed
		return
	}

	newTB := newBundle.(*trustedBundle)
	tb.update(newTB.raw, newTB.metadata, newTB.catalog)

	// Persist the updated bundle if local cache is enabled
	if !cfg.GetDisableLocalCache() {
		// Ignore error as persistence failure shouldn't stop the update
		_ = tb.Persist(cfg.GetCachePath())
	}
}
