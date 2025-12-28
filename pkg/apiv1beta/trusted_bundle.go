package apiv1beta

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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
//	metadata := tb.GetRootMetadata()
type TrustedBundle interface {
	// GetRawRoot returns the raw PEM-encoded root bundle.
	GetRawRoot() []byte

	// GetRawIntermediate returns the raw PEM-encoded intermediate bundle if available.
	// Returns nil if the intermediate bundle is not present in the release.
	GetRawIntermediate() []byte

	// GetRootMetadata returns the root bundle metadata (date and commit).
	GetRootMetadata() *bundle.Metadata

	// GetIntermediateMetadata returns the intermediate bundle metadata if available.
	// Returns nil if the intermediate bundle is not present in the release.
	GetIntermediateMetadata() *bundle.Metadata

	// GetVendors returns the list of vendor IDs in the bundle.
	GetVendors() []VendorID

	// GetRoots returns an [x509.CertPool] containing all certificates from the bundle,
	// or only certificates from specified vendors if the bundle was created with VendorIDs filter.
	GetRoots() *x509.CertPool

	// GetIntermediates returns an [x509.CertPool] containing all intermediate certificates from the bundle,
	// or only intermediate certificates from specified vendors if the bundle was created with VendorIDs filter.
	GetIntermediates() *x509.CertPool

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
	mu                   sync.RWMutex
	assets               *assets
	rootMetadata         *bundle.Metadata
	intermediateMetadata *bundle.Metadata
	rootCatalog          map[vendors.ID][]*x509.Certificate
	intermediateCatalog  map[vendors.ID][]*x509.Certificate

	// vendorFilter is the list of vendors to filter when calling GetRoots.
	// If empty, all certificates are returned.
	vendorFilter []VendorID

	autoUpdateCfg     *AutoUpdateConfig
	disableLocalCache bool

	// Auto-update fields
	stopChan    chan struct{}
	stoppedChan chan struct{}
	stopOnce    sync.Once
}

// GetRawRoot returns the raw PEM-encoded bundle.
func (tb *trustedBundle) GetRawRoot() []byte {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	// Return a copy to prevent external modifications
	return slices.Clone(tb.assets.rootBundleData)
}

// GetRawIntermediate returns the raw PEM-encoded intermediate bundle if available.
func (tb *trustedBundle) GetRawIntermediate() []byte {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	// Return a copy to prevent external modifications
	return slices.Clone(tb.assets.intermediateBundleData)
}

// GetRootMetadata returns the bundle metadata.
func (tb *trustedBundle) GetRootMetadata() *bundle.Metadata {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	// Return a copy to prevent external modifications
	metadata := *tb.rootMetadata
	return &metadata
}

// GetIntermediateMetadata returns the intermediate bundle metadata if available.
func (tb *trustedBundle) GetIntermediateMetadata() *bundle.Metadata {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	if tb.intermediateMetadata == nil {
		return nil
	}

	// Return a copy to prevent external modifications
	metadata := *tb.intermediateMetadata
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
			if _, ok := tb.rootCatalog[vendorID]; ok {
				vendors = append(vendors, vendorID)
			}
		}
		return vendors
	}

	vendors := make([]VendorID, 0, len(tb.rootCatalog))
	for vendorID := range tb.rootCatalog {
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

	return tb.buildCertPool(tb.rootCatalog)
}

// GetIntermediates returns an x509.CertPool containing intermediate certificates.
//
// If the bundle was created with VendorIDs filter, only certificates from those vendors are included.
// Otherwise, all certificates from the bundle are included.
// Returns an empty pool if no intermediate bundle is available.
func (tb *trustedBundle) GetIntermediates() *x509.CertPool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	return tb.buildCertPool(tb.intermediateCatalog)
}

// buildCertPool creates an x509.CertPool from the given catalog, applying vendor filters if configured.
func (tb *trustedBundle) buildCertPool(catalog map[vendors.ID][]*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()

	// If no vendor filter, add all certificates
	if len(tb.vendorFilter) == 0 {
		for _, certs := range catalog {
			for _, cert := range certs {
				pool.AddCert(cert)
			}
		}
		return pool
	}

	// Add only certificates from specified vendors
	for _, vendorID := range tb.vendorFilter {
		if certs, ok := catalog[vendorID]; ok {
			for _, cert := range certs {
				pool.AddCert(cert)
			}
		}
	}

	return pool
}

// Persist writes the bundle and its configuration to disk.
func (tb *trustedBundle) Persist(optionalCachePath ...string) error {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	if tb.disableLocalCache {
		return ErrCannotPersistTrustedBundle
	}

	cachePath := filepath.Clean(
		utils.OptionalArgWithDefault(optionalCachePath, cache.CacheDir()),
	)

	if !utils.DirExists(cachePath) {
		if err := os.MkdirAll(cachePath, 0700); err != nil {
			return fmt.Errorf("failed to create cache directory: %w", err)
		}
	}

	// Write core bundle assets
	if err := writeBundleAssets(cachePath, tb.assets.rootBundleData, tb.assets.checksum, tb.assets.checksumSignature, tb.assets.provenance); err != nil {
		return err
	}

	// Write intermediate bundle if present
	if len(tb.assets.intermediateBundleData) > 0 {
		if err := cache.SaveFile(cache.IntermediateBundleFilename, tb.assets.intermediateBundleData, cachePath); err != nil {
			return err
		}
	}

	skipVerify := (len(tb.assets.checksum) == 0 &&
		len(tb.assets.checksumSignature) == 0 &&
		len(tb.assets.provenance) == 0)

	cfg := CacheConfig{
		Version:       tb.rootMetadata.Date,
		AutoUpdate:    tb.autoUpdateCfg,
		VendorIDs:     tb.vendorFilter,
		LastTimestamp: time.Now(),
		SkipVerify:    skipVerify,
	}

	configData, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := cache.SaveFile(cache.ConfigFilename, configData, cachePath); err != nil {
		return err
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

	select {
	case <-tb.stoppedChan:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for auto-update watcher to stop")
	}
}

// update atomically updates the bundle data.
func (tb *trustedBundle) update(assets *assets, metadata *bundle.Metadata, intermediateMetadata *bundle.Metadata, catalog map[vendors.ID][]*x509.Certificate) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.assets = assets
	tb.rootMetadata = metadata
	tb.intermediateMetadata = intermediateMetadata
	tb.rootCatalog = catalog
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

func (c LoadConfig) GetHttpClient() utils.HttpClient {
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

	rootBundleData, err := cache.LoadFile(cache.RootBundleFilename, cfg.CachePath)
	if err != nil {
		return nil, err
	}
	// first releases did not have intermediate bundle
	// so we ignore os.ErrNotExist here
	intermediateBundleData, err := cache.LoadFile(cache.IntermediateBundleFilename, cfg.CachePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	configData, err := cache.LoadFile(cache.ConfigFilename, cfg.CachePath)
	if err != nil {
		return nil, err
	}

	var cacheCfg CacheConfig
	if err := json.Unmarshal(configData, &cacheCfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := cacheCfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	var skipVerify bool
	switch {
	// user has highest priority
	case cfg.SkipVerify:
		skipVerify = true
	default:
		// then we fallback to cached config
		skipVerify = cacheCfg.SkipVerify
	}

	var checksumData, checksumSigData, provenanceData, trustedRootData []byte
	if !skipVerify {
		var err error
		checksumData, err = cache.LoadFile(cache.ChecksumsFilename, cfg.CachePath)
		if err != nil {
			return nil, err
		}

		checksumSigData, err = cache.LoadFile(cache.ChecksumsSigFilename, cfg.CachePath)
		if err != nil {
			return nil, err
		}

		provenanceData, err = cache.LoadFile(cache.ProvenanceFilename, cfg.CachePath)
		if err != nil {
			return nil, err
		}

		// In offline mode, load trusted-root.json from cache
		if cfg.OfflineMode {
			trustedRootData, err = cache.LoadFile(cache.TrustedRootFilename, cfg.CachePath)
			if err != nil {
				return nil, err
			}
		}

		if _, err := VerifyTrustedBundle(ctx, VerifyConfig{
			Bundle:            rootBundleData,
			Checksum:          checksumData,
			ChecksumSignature: checksumSigData,
			Provenance:        provenanceData,
			TrustedRoot:       trustedRootData,
			DisableLocalCache: cfg.DisableLocalCache,
		}); err != nil {
			return nil, fmt.Errorf("root verification failed: %w", err)
		}
		// we do this check for backward compatibility
		if len(intermediateBundleData) > 0 {
			if _, err := VerifyTrustedBundle(ctx, VerifyConfig{
				Bundle:            intermediateBundleData,
				Checksum:          checksumData,
				ChecksumSignature: checksumSigData,
				Provenance:        provenanceData,
				TrustedRoot:       trustedRootData,
				DisableLocalCache: cfg.DisableLocalCache,
			}); err != nil {
				return nil, fmt.Errorf("intermediate bundle verification failed: %w", err)
			}
		}
	}

	tb, err := newTrustedBundle(rootBundleData, intermediateBundleData)
	if err != nil {
		return nil, err
	}

	// Store vendor filter and verification assets
	tbImpl := tb.(*trustedBundle)
	tbImpl.vendorFilter = cacheCfg.VendorIDs
	tbImpl.autoUpdateCfg = cacheCfg.AutoUpdate
	tbImpl.assets.checksum = checksumData
	tbImpl.assets.checksumSignature = checksumSigData
	tbImpl.assets.provenance = provenanceData

	// In offline mode, auto-update must be disabled since the cached trusted-root.json
	// may not work with future bundles due to Sigstore key rotation
	if cacheCfg.AutoUpdate != nil {
		if !cfg.OfflineMode && !cacheCfg.AutoUpdate.DisableAutoUpdate {
			tb.(*trustedBundle).startWatcher(ctx, cfg, cacheCfg.AutoUpdate.Interval)
		}
	}
	return tb, nil
}

type updaterConfig interface {
	GetHttpClient() utils.HttpClient
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
	currentMetadata := tb.GetRootMetadata()
	newMetadata := newBundle.GetRootMetadata()
	if newMetadata.Date <= currentMetadata.Date {
		// No update needed
		return
	}

	newTB := newBundle.(*trustedBundle)
	tb.update(newTB.assets, newTB.rootMetadata, newTB.intermediateMetadata, newTB.rootCatalog)

	// Persist the updated bundle if local cache is enabled
	if !cfg.GetDisableLocalCache() {
		// Ignore error as persistence failure shouldn't stop the update
		_ = tb.Persist(cfg.GetCachePath())
	}
}

// newTrustedBundle creates a TrustedBundle from raw bundle data.
func newTrustedBundle(bundles ...[]byte) (TrustedBundle, error) {
	tb := &trustedBundle{
		assets: &assets{},
	}
	for _, b := range bundles {
		if len(b) == 0 {
			continue
		}
		metadata, err := bundle.ParseMetadata(b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bundle metadata: %w", err)
		}

		catalog, err := bundle.ParseBundle(b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bundle: %w", err)
		}

		if metadata.Type == bundle.TypeRoot {
			tb.assets.rootBundleData = b
			tb.rootMetadata = metadata
			tb.rootCatalog = catalog
		}
		if metadata.Type == bundle.TypeIntermediate {
			tb.assets.intermediateBundleData = b
			tb.intermediateMetadata = metadata
			tb.intermediateCatalog = catalog
		}
	}
	return tb, nil
}
