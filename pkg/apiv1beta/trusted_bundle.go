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

	// GetVerifyOptions returns [x509.VerifyOptions] configured for TPM certificate verification.
	GetVerifyOptions() x509.VerifyOptions

	// VerifyCertificate verifies a certificate against the bundle's trust anchors.
	//
	// This method handles TPM-specific certificate quirks:
	//   - Clears UnhandledCriticalExtensions to work around TPM-specific OIDs
	//
	// Returns an error if the certificate cannot be verified.
	VerifyCertificate(cert *x509.Certificate) error

	// Contains checks if a certificate is stored in the bundle.
	//
	// Returns true if the certificate is found in either the root or intermediate catalogs.
	Contains(cert *x509.Certificate) bool

	// Persist marshals bundle and its verification assets to disk at the specified cache path.
	//
	// Notes:
	//  * variadic optionalCachePath argument is optional. If not provided, the default cache path is used.
	//  * if the files already exist, they will be overwritten.
	//  * use [Load] to reconstruct [TrustedBundle] from persisted files.
	Persist(optionalCachePath ...string) error

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

// forEachCert iterates over certificates in the catalog, applying vendor filters if configured.
// The callback function is called for each certificate. If the callback returns false, iteration stops.
func (tb *trustedBundle) forEachCert(catalog map[vendors.ID][]*x509.Certificate, fn func(*x509.Certificate) bool) {
	// If no vendor filter, iterate all certificates
	if len(tb.vendorFilter) == 0 {
		for _, certs := range catalog {
			for _, cert := range certs {
				if !fn(cert) {
					return
				}
			}
		}
		return
	}

	// Iterate only certificates from specified vendors
	for _, vendorID := range tb.vendorFilter {
		if certs, ok := catalog[vendorID]; ok {
			for _, cert := range certs {
				if !fn(cert) {
					return
				}
			}
		}
	}
}

// buildCertPool creates an x509.CertPool from the given catalog, applying vendor filters if configured.
func (tb *trustedBundle) buildCertPool(catalog map[vendors.ID][]*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	tb.forEachCert(catalog, func(cert *x509.Certificate) bool {
		pool.AddCert(cert)
		return true
	})
	return pool
}

// GetVerifyOptions returns x509.VerifyOptions configured for TPM certificate verification.
func (tb *trustedBundle) GetVerifyOptions() x509.VerifyOptions {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	return x509.VerifyOptions{
		Roots:         tb.buildCertPool(tb.rootCatalog),
		Intermediates: tb.buildCertPool(tb.intermediateCatalog),
		// TPM EK certificates don't have standard key usages, so we need to allow any usage
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}

// VerifyCertificate verifies a certificate against the bundle's trust anchors.
func (tb *trustedBundle) VerifyCertificate(cert *x509.Certificate) error {
	// Copy the EK certificate and mark all critical extensions as handled
	// to work around TPM-specific OIDs that x509 doesn't recognize
	ekCopy := *cert
	ekCopy.UnhandledCriticalExtensions = nil

	opts := tb.GetVerifyOptions()
	_, err := ekCopy.Verify(opts)
	return err
}

// Contains checks if a certificate is stored in the bundle.
//
// If the bundle was created with VendorIDs filter, only certificates from those vendors are checked.
// Otherwise, all certificates from the bundle are checked.
func (tb *trustedBundle) Contains(cert *x509.Certificate) bool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	return tb.containsInCatalog(cert, tb.rootCatalog) || tb.containsInCatalog(cert, tb.intermediateCatalog)
}

// containsInCatalog checks if a certificate is in the given catalog, applying vendor filters if configured.
func (tb *trustedBundle) containsInCatalog(cert *x509.Certificate, catalog map[vendors.ID][]*x509.Certificate) bool {
	found := false
	tb.forEachCert(catalog, func(c *x509.Certificate) bool {
		if c.Equal(cert) {
			found = true
			return false // Stop iteration
		}
		return true // Continue iteration
	})
	return found
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

	return persistAllBundleAssets(
		cachePath,
		tb.assets.rootBundleData,
		tb.assets.intermediateBundleData,
		tb.assets.checksum,
		tb.assets.checksumSignature,
		tb.assets.provenance,
		/* trustedBundle */ nil,
		configData,
	)
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

// LoadTrustedBundle reads a persisted [TrustedBundle] from disk and verifies its integrity.
//
// Example:
//
//	tb, err := apiv1beta.LoadTrustedBundle(context.Background(), apiv1beta.LoadConfig{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer tb.Stop()
func LoadTrustedBundle(ctx context.Context, cfg LoadConfig) (TrustedBundle, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, err
	}

	rootBundleData, err := cache.LoadFile(cfg.CachePath, cache.RootBundleFilename)
	if err != nil {
		return nil, err
	}
	// first releases did not have intermediate bundle
	// so we ignore [os.ErrNotExist] here
	intermediateBundleData, err := cache.LoadFile(cfg.CachePath, cache.IntermediateBundleFilename)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	configData, err := cache.LoadFile(cfg.CachePath, cache.ConfigFilename)
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
		checksumData, err = cache.LoadFile(cfg.CachePath, cache.ChecksumsFilename)
		if err != nil {
			return nil, err
		}

		checksumSigData, err = cache.LoadFile(cfg.CachePath, cache.ChecksumsSigFilename)
		if err != nil {
			return nil, err
		}

		provenanceData, err = cache.LoadFile(cfg.CachePath, cache.ProvenanceFilename)
		if err != nil {
			return nil, err
		}

		// In offline mode, load trusted-root.json from cache
		if cfg.OfflineMode {
			trustedRootData, err = cache.LoadFile(cfg.CachePath, cache.TrustedRootFilename)
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
	GetHTTPClient() utils.HTTPClient
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
		HTTPClient: cfg.GetHTTPClient(),
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
