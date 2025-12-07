package apiv1beta

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/vendors"
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
func (tb *trustedBundle) GetVendors() []VendorID {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

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
	DisableAutoUpdate bool

	// Interval specifies how often the bundle should be updated.
	//
	// Optional. If zero, the default interval of 24 hours is used.
	Interval time.Duration
}

// CheckAndSetDefaults validates and sets default values.
func (c *AutoUpdateConfig) CheckAndSetDefaults() error {
	if c.Interval == 0 && !c.DisableAutoUpdate {
		c.Interval = 24 * time.Hour
	}
	return nil
}

// startWatcher starts the auto-update watcher in a background goroutine.
func (tb *trustedBundle) startWatcher(ctx context.Context, cfg GetConfig, interval time.Duration) {
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
func (tb *trustedBundle) checkAndUpdate(ctx context.Context, cfg GetConfig) {
	// Fetch the latest bundle without starting a watcher
	newBundle, err := GetTrustedBundle(ctx, GetConfig{
		Date:       "", // Always fetch latest
		SkipVerify: cfg.SkipVerify,
		HTTPClient: cfg.HTTPClient,
		AutoUpdate: AutoUpdateConfig{
			DisableAutoUpdate: true, // Don't start a watcher for this temporary bundle
		},
		sourceRepo: cfg.sourceRepo,
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

	// Extract internal data from the new bundle
	newTB := newBundle.(*trustedBundle)

	// Update atomically
	tb.update(newTB.raw, newTB.metadata, newTB.catalog)
}
