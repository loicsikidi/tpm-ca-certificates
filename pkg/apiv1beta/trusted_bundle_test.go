package apiv1beta

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/loicsikidi/go-tpm-kit/tpmcert/ekca"
	"github.com/loicsikidi/go-tpm-kit/tpmcert/x509ext"
	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/vendors"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

func TestGetTrustedBundle(t *testing.T) {

	t.Run("invalid vendor ID", func(t *testing.T) {
		cfg := GetConfig{
			SkipVerify: true,
			VendorIDs:  []VendorID{"INVALID_VENDOR"},
			AutoUpdate: AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		_, err := GetTrustedBundle(t.Context(), cfg)
		if err == nil {
			t.Fatal("Expected error for invalid vendor ID")
		}
	})
}

func TestPersist(t *testing.T) {
	t.Run("persist and verify files", func(t *testing.T) {
		tmpDir := t.TempDir()

		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}
		tb.(*trustedBundle).vendorFilter = []VendorID{IFX}

		// Persist the bundle
		if err := tb.Persist(context.Background(), tmpDir); err != nil {
			t.Fatalf("Failed to persist bundle: %v", err)
		}

		// Verify bundle.pem exists
		bundlePath := filepath.Join(tmpDir, CacheRootBundleFilename)
		if !utils.FileExists(bundlePath) {
			t.Fatalf("Bundle file not found at %s", bundlePath)
		}

		// Verify config.json exists
		configPath := filepath.Join(tmpDir, CacheConfigFilename)
		if !utils.FileExists(configPath) {
			t.Fatalf("Config file not found at %s", configPath)
		}

		// Read and verify bundle content
		persistedBundle, err := utils.ReadFile(bundlePath)
		if err != nil {
			t.Fatalf("Failed to read bundle file: %v", err)
		}
		if len(persistedBundle) == 0 {
			t.Fatal("Bundle file is empty")
		}

		// Read and verify config content
		configData, err := utils.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config file: %v", err)
		}
		if len(configData) == 0 {
			t.Fatal("Config file is empty")
		}
	})

	t.Run("persist overwrites existing files", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create initial files
		bundlePath := filepath.Join(tmpDir, CacheRootBundleFilename)
		configPath := filepath.Join(tmpDir, CacheConfigFilename)

		if err := os.WriteFile(bundlePath, []byte("old bundle"), 0644); err != nil {
			t.Fatalf("Failed to create initial bundle: %v", err)
		}
		if err := os.WriteFile(configPath, []byte("old config"), 0644); err != nil {
			t.Fatalf("Failed to create initial config: %v", err)
		}

		// Load and persist new bundle
		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		if err := tb.Persist(context.Background(), tmpDir); err != nil {
			t.Fatalf("Failed to persist bundle: %v", err)
		}

		// Verify files were overwritten
		bundleContent, _ := utils.ReadFile(bundlePath)
		if string(bundleContent) == "old bundle" {
			t.Fatal("Bundle file was not overwritten")
		}

		configContent, _ := utils.ReadFile(configPath)
		if string(configContent) == "old config" {
			t.Fatal("Config file was not overwritten")
		}
	})
}

func TestGetVendors(t *testing.T) {
	t.Run("returns all vendors when no filter", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		vendors := tb.GetVendors()
		if len(vendors) == 0 {
			t.Fatal("Expected at least one vendor")
		}

		// Verify we get all vendors from the catalog
		tbImpl := tb.(*trustedBundle)
		if len(vendors) != len(tbImpl.rootCatalog) {
			t.Fatalf("Expected %d vendors, got %d", len(tbImpl.rootCatalog), len(vendors))
		}
	})

	t.Run("returns only filtered vendors with certificates", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		tbImpl := tb.(*trustedBundle)
		tbImpl.vendorFilter = []VendorID{IFX}

		vendors := tb.GetVendors()
		if len(vendors) != 1 {
			t.Fatalf("Expected 1 vendor, got %d", len(vendors))
		}
		if vendors[0] != IFX {
			t.Fatalf("Expected IFX vendor, got %v", vendors[0])
		}
	})

	t.Run("excludes filtered vendors without certificates", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		tbImpl := tb.(*trustedBundle)
		// Set filter with a vendor that doesn't exist
		tbImpl.vendorFilter = []VendorID{"NON_EXISTENT_VENDOR"}

		vendors := tb.GetVendors()
		if len(vendors) != 0 {
			t.Fatalf("Expected 0 vendors, got %d", len(vendors))
		}
	})

	t.Run("returns only filtered vendors that exist in catalog", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		tbImpl := tb.(*trustedBundle)
		// Mix existing and non-existing vendors
		tbImpl.vendorFilter = []VendorID{IFX, "NON_EXISTENT"}

		vendors := tb.GetVendors()
		if len(vendors) != 1 {
			t.Fatalf("Expected 1 vendor, got %d", len(vendors))
		}
		if vendors[0] != IFX {
			t.Fatalf("Expected IFX vendor, got %v", vendors[0])
		}
	})

	t.Run("returns empty slice when catalog is empty", func(t *testing.T) {
		tb := &trustedBundle{
			rootCatalog: make(map[VendorID][]*x509.Certificate),
		}

		vendors := tb.GetVendors()
		if len(vendors) != 0 {
			t.Fatalf("Expected 0 vendors, got %d", len(vendors))
		}
	})
}

func TestLoadOfflineMode(t *testing.T) {

	t.Run("loads bundle successfully in offline mode", func(t *testing.T) {
		// Create cache with all required files including trusted-root.json
		cacheDir := testutil.CreateCacheDir(t, nil)

		// Load in offline mode
		tb, err := LoadTrustedBundle(t.Context(), LoadConfig{
			CachePath:   cacheDir,
			OfflineMode: true,
		})
		if err != nil {
			t.Fatalf("Failed to load bundle in offline mode: %v", err)
		}
		defer tb.Stop()

		// Verify bundle was loaded
		roots := tb.GetRootCertPool()
		if roots == nil {
			t.Fatal("Expected roots to be non-nil")
		}

		// Verify we have at least one vendor
		vendors := tb.GetVendors()
		if len(vendors) == 0 {
			t.Fatal("Expected at least one vendor")
		}
	})

	t.Run("fails when trusted-root.json is missing in offline mode", func(t *testing.T) {
		// Create cache without trusted-root.json
		tmpDir := t.TempDir()

		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		// Create minimal cache (missing trusted-root.json)
		bundlePath := filepath.Join(tmpDir, CacheRootBundleFilename)
		if err := os.WriteFile(bundlePath, bundleData, 0644); err != nil {
			t.Fatalf("Failed to write bundle: %v", err)
		}

		configPath := filepath.Join(tmpDir, CacheConfigFilename)
		configData := []byte(`{"version":"2025-12-14","autoUpdate":{"disableAutoUpdate":true}}`)
		if err := os.WriteFile(configPath, configData, 0644); err != nil {
			t.Fatalf("Failed to write config: %v", err)
		}

		// Load other verification assets
		for _, filename := range []string{
			testutil.ChecksumFile,
			testutil.ChecksumSigstoreFile,
			testutil.ProvenanceFile,
		} {
			data, err := testutil.ReadTestFile(filename)
			if err != nil {
				t.Fatalf("Failed to read test file %s: %v", filename, err)
			}
			destPath := filepath.Join(tmpDir, filename)
			if err := os.WriteFile(destPath, data, 0644); err != nil {
				t.Fatalf("Failed to write file %s: %v", filename, err)
			}
		}

		// Try to load in offline mode - should fail
		_, err = LoadTrustedBundle(t.Context(), LoadConfig{
			CachePath:   tmpDir,
			OfflineMode: true,
		})
		if err == nil {
			t.Fatal("Expected error when trusted-root.json is missing in offline mode")
		}
	})

	t.Run("fails when offline mode requires local cache", func(t *testing.T) {
		cacheDir := testutil.CreateCacheDir(t, nil)

		_, err := LoadTrustedBundle(t.Context(), LoadConfig{
			CachePath:         cacheDir,
			OfflineMode:       true,
			DisableLocalCache: true,
		})
		if err == nil {
			t.Fatal("Expected error when offline mode is enabled with DisableLocalCache=true")
		}
	})

	t.Run("disables auto-update in offline mode", func(t *testing.T) {
		// Create cache with auto-update enabled
		configData := []byte(`{
			"version":"` + testutil.BundleVersion + `",
			"autoUpdate":{"disableAutoUpdate":false},
			"vendorIDs":[],
			"lastTimestamp":"2025-12-14T00:00:00Z"
		}`)
		cacheDir := testutil.CreateCacheDir(t, configData)

		tb, err := LoadTrustedBundle(t.Context(), LoadConfig{
			CachePath:   cacheDir,
			OfflineMode: true,
		})
		if err != nil {
			t.Fatalf("Failed to load bundle in offline mode: %v", err)
		}
		defer tb.Stop()

		// Verify auto-update is disabled (watcher should not be running)
		tbImpl := tb.(*trustedBundle)
		if tbImpl.stopChan != nil {
			t.Fatal("Expected watcher to be disabled in offline mode")
		}
	})
}

func TestLoadConfigValidation(t *testing.T) {
	t.Run("rejects offline mode with disabled local cache", func(t *testing.T) {
		cfg := LoadConfig{
			CachePath:         t.TempDir(),
			OfflineMode:       true,
			DisableLocalCache: true,
		}

		err := cfg.CheckAndSetDefaults()
		if err == nil {
			t.Fatal("Expected error when offline mode is enabled with DisableLocalCache=true")
		}
	})
}

func Test_getVerifyOptions(t *testing.T) {
	t.Run("returns verify options with roots and intermediates", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		tbImpl := tb.(*trustedBundle)
		opts := tbImpl.getVerifyOptions()

		if opts.Roots == nil {
			t.Fatal("Expected Roots to be non-nil")
		}

		if opts.Intermediates == nil {
			t.Fatal("Expected Intermediates to be non-nil")
		}

		if len(opts.KeyUsages) != 1 || opts.KeyUsages[0] != x509.ExtKeyUsageAny {
			t.Fatalf("Expected KeyUsages to contain ExtKeyUsageAny, got %v", opts.KeyUsages)
		}
	})

	t.Run("handles missing intermediate bundle", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		// Clear intermediate catalog to simulate missing intermediates
		tbImpl := tb.(*trustedBundle)
		tbImpl.intermediateCatalog = nil

		opts := tbImpl.getVerifyOptions()

		if opts.Roots == nil {
			t.Fatal("Expected Roots to be non-nil")
		}

		// Intermediates should be an empty pool (not nil)
		if opts.Intermediates == nil {
			t.Fatal("Expected Intermediates to be non-nil (empty pool)")
		}
	})
}

func TestVerify(t *testing.T) {
	t.Run("verifies valid EK certificate with complete chain", func(t *testing.T) {
		setup := setupVerifyTest(t, vendors.GOOG, true /* includeIntermediate */)

		err := setup.trustedBundle.Verify(setup.ekCert)
		if err != nil {
			t.Fatalf("Failed to verify certificate: %v", err)
		}
	})

	t.Run("verifies valid EK certificate with root-only bundle", func(t *testing.T) {
		setup := setupVerifyTest(t, vendors.GOOG, false /* includeIntermediate */)

		err := setup.trustedBundle.Verify(setup.ekCert, []*x509.Certificate{setup.ca.Intermediate})
		if err != nil {
			t.Fatalf("Failed to verify certificate with optional chain: %v", err)
		}
	})

	t.Run("verifies it's not possible to add root cert in optional chain", func(t *testing.T) {
		setup := setupVerifyTest(t, vendors.GOOG, true /* includeIntermediate */)
		setup2 := setupVerifyTest(t, vendors.SNS, true /* includeIntermediate */)

		chain := []*x509.Certificate{setup.ca.Intermediate, setup2.ca.Root}
		err := setup.trustedBundle.Verify(setup2.ekCert, chain)
		if err == nil {
			t.Fatalf("Expected verification to fail when adding root cert in optional chain")
		}
	})

	t.Run("fails to verify certificate from untrusted CA", func(t *testing.T) {
		setup1 := setupVerifyTest(t, vendors.GOOG, true /* includeIntermediate */)
		setup2 := setupVerifyTest(t, vendors.SNS, true /* includeIntermediate */)

		err := setup1.trustedBundle.Verify(setup2.ekCert)
		if err == nil {
			t.Fatal("Expected verification to fail for certificate from untrusted CA")
		}
	})
}

func TestContains(t *testing.T) {
	t.Run("returns true when certificate is in the bundle", func(t *testing.T) {
		setup := setupVerifyTest(t, vendors.GOOG, true /* includeIntermediate */)

		if !setup.trustedBundle.Contains(setup.ca.Intermediate) {
			t.Fatal("Expected Contains to return true for certificate in the bundle")
		}

		if !setup.trustedBundle.Contains(setup.ca.Root) {
			t.Fatal("Expected Contains to return true for root certificate in the bundle")
		}
	})

	t.Run("returns false for certificate not in bundle", func(t *testing.T) {
		setup := setupVerifyTest(t, vendors.GOOG, true /* includeIntermediate */)
		missingCert := setupVerifyTest(t, vendors.SNS, false /* includeIntermediate */).ca.Root

		if setup.trustedBundle.Contains(missingCert) {
			t.Fatal("Expected Contains to return false for certificate not in bundle")
		}
	})

	t.Run("returns false for empty bundle", func(t *testing.T) {
		tb := &trustedBundle{
			rootCatalog:         make(map[VendorID][]*x509.Certificate),
			intermediateCatalog: make(map[VendorID][]*x509.Certificate),
		}

		setup := setupVerifyTest(t, vendors.GOOG, false /* includeIntermediate */)

		if tb.Contains(setup.ca.Intermediate) {
			t.Fatal("Expected Contains to return false for empty bundle")
		}
	})

	t.Run("respects vendor filter - returns true for filtered vendor", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		tbImpl := tb.(*trustedBundle)

		// Get a certificate from IFX vendor
		var ifxCert *x509.Certificate
		if certs, ok := tbImpl.rootCatalog[IFX]; ok && len(certs) > 0 {
			ifxCert = certs[0]
		}

		if ifxCert == nil {
			t.Skip("No IFX certificates found in bundle")
		}

		// Set vendor filter to IFX only
		tbImpl.vendorFilter = []VendorID{IFX}

		// Should return true for IFX certificate
		if !tb.Contains(ifxCert) {
			t.Fatal("Expected Contains to return true for certificate from filtered vendor")
		}
	})

	t.Run("respects vendor filter - returns false for non-filtered vendor", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		tbImpl := tb.(*trustedBundle)

		// Get a certificate from IFX vendor
		var ifxCert *x509.Certificate
		if certs, ok := tbImpl.rootCatalog[IFX]; ok && len(certs) > 0 {
			ifxCert = certs[0]
		}

		if ifxCert == nil {
			t.Skip("No IFX certificates found in bundle")
		}

		// Set vendor filter to exclude IFX (use a different vendor)
		var otherVendor VendorID
		for vendorID := range tbImpl.rootCatalog {
			if vendorID != IFX {
				otherVendor = vendorID
				break
			}
		}

		if otherVendor == "" {
			t.Skip("Need at least two different vendors in bundle")
		}

		tbImpl.vendorFilter = []VendorID{otherVendor}

		// Should return false for IFX certificate when filter excludes it
		if tb.Contains(ifxCert) {
			t.Fatal("Expected Contains to return false for certificate from non-filtered vendor")
		}
	})

	t.Run("respects vendor filter - empty filter checks all vendors", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		tbImpl := tb.(*trustedBundle)

		// Get a certificate from any vendor
		var testCert *x509.Certificate
		for _, certs := range tbImpl.rootCatalog {
			if len(certs) > 0 {
				testCert = certs[0]
				break
			}
		}

		if testCert == nil {
			t.Skip("No certificates found in bundle")
		}

		// With no vendor filter, should find the certificate
		tbImpl.vendorFilter = nil

		if !tb.Contains(testCert) {
			t.Fatal("Expected Contains to return true when no vendor filter is set")
		}
	})
}

func TestContainsFunc(t *testing.T) {
	bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
	if err != nil {
		t.Fatalf("Failed to read test bundle: %v", err)
	}

	tests := []struct {
		name      string
		setupFunc func(t *testing.T) (TrustedBundle, func(c *x509.Certificate) bool, bool)
	}{
		{
			name: "returns true when predicate matches certificate in root catalog",
			setupFunc: func(t *testing.T) (TrustedBundle, func(c *x509.Certificate) bool, bool) {
				tb, err := newTrustedBundle(t.Context(), bundleData)
				if err != nil {
					t.Fatalf("Failed to create trusted bundle: %v", err)
				}

				tbImpl := tb.(*trustedBundle)
				var testCert *x509.Certificate
				for _, certs := range tbImpl.rootCatalog {
					if len(certs) > 0 {
						testCert = certs[0]
						break
					}
				}

				if testCert == nil {
					t.Fatal("No certificates found in root catalog")
				}

				predicate := func(c *x509.Certificate) bool {
					return c.Subject.String() == testCert.Subject.String()
				}

				return tb, predicate, true
			},
		},
		{
			name: "returns false when predicate matches no certificates",
			setupFunc: func(t *testing.T) (TrustedBundle, func(c *x509.Certificate) bool, bool) {
				tb, err := newTrustedBundle(t.Context(), bundleData)
				if err != nil {
					t.Fatalf("Failed to create trusted bundle: %v", err)
				}

				predicate := func(c *x509.Certificate) bool {
					return c.Subject.CommonName == "NonExistentCertificate"
				}

				return tb, predicate, false
			},
		},
		{
			name: "returns false for empty bundle",
			setupFunc: func(t *testing.T) (TrustedBundle, func(c *x509.Certificate) bool, bool) {
				tb := &trustedBundle{
					rootCatalog:         make(map[VendorID][]*x509.Certificate),
					intermediateCatalog: make(map[VendorID][]*x509.Certificate),
				}

				predicate := func(c *x509.Certificate) bool {
					return true
				}

				return tb, predicate, false
			},
		},
		{
			name: "respects vendor filter - returns true for filtered vendor",
			setupFunc: func(t *testing.T) (TrustedBundle, func(c *x509.Certificate) bool, bool) {
				tb, err := newTrustedBundle(t.Context(), bundleData)
				if err != nil {
					t.Fatalf("Failed to create trusted bundle: %v", err)
				}

				tbImpl := tb.(*trustedBundle)
				var ifxCert *x509.Certificate
				if certs, ok := tbImpl.rootCatalog[IFX]; ok && len(certs) > 0 {
					ifxCert = certs[0]
				}

				if ifxCert == nil {
					t.Skip("No IFX certificates found in bundle")
				}

				tbImpl.vendorFilter = []VendorID{IFX}

				predicate := func(c *x509.Certificate) bool {
					return c.Subject.String() == ifxCert.Subject.String()
				}

				return tb, predicate, true
			},
		},
		{
			name: "respects vendor filter - returns false for non-filtered vendor",
			setupFunc: func(t *testing.T) (TrustedBundle, func(c *x509.Certificate) bool, bool) {
				tb, err := newTrustedBundle(t.Context(), bundleData)
				if err != nil {
					t.Fatalf("Failed to create trusted bundle: %v", err)
				}

				tbImpl := tb.(*trustedBundle)
				var ifxCert *x509.Certificate
				if certs, ok := tbImpl.rootCatalog[IFX]; ok && len(certs) > 0 {
					ifxCert = certs[0]
				}

				if ifxCert == nil {
					t.Skip("No IFX certificates found in bundle")
				}

				var otherVendor VendorID
				for vendorID := range tbImpl.rootCatalog {
					if vendorID != IFX {
						otherVendor = vendorID
						break
					}
				}

				if otherVendor == "" {
					t.Skip("Need at least two different vendors in bundle")
				}

				tbImpl.vendorFilter = []VendorID{otherVendor}

				predicate := func(c *x509.Certificate) bool {
					return c.Subject.String() == ifxCert.Subject.String()
				}

				return tb, predicate, false
			},
		},
		{
			name: "checks certificates in intermediate catalog",
			setupFunc: func(t *testing.T) (TrustedBundle, func(c *x509.Certificate) bool, bool) {
				tb, err := newTrustedBundle(t.Context(), bundleData)
				if err != nil {
					t.Fatalf("Failed to create trusted bundle: %v", err)
				}

				tbImpl := tb.(*trustedBundle)
				var testCert *x509.Certificate
				for _, certs := range tbImpl.rootCatalog {
					if len(certs) > 0 {
						testCert = certs[0]
						break
					}
				}

				if testCert == nil {
					t.Skip("No certificates found in root catalog")
				}

				tbImpl.intermediateCatalog = map[VendorID][]*x509.Certificate{
					IFX: {testCert},
				}
				tbImpl.rootCatalog = make(map[VendorID][]*x509.Certificate)

				predicate := func(c *x509.Certificate) bool {
					return c.Subject.String() == testCert.Subject.String()
				}

				return tb, predicate, true
			},
		},
		{
			name: "stops iteration when predicate returns true",
			setupFunc: func(t *testing.T) (TrustedBundle, func(c *x509.Certificate) bool, bool) {
				tb, err := newTrustedBundle(t.Context(), bundleData)
				if err != nil {
					t.Fatalf("Failed to create trusted bundle: %v", err)
				}

				callCount := 0
				predicate := func(c *x509.Certificate) bool {
					callCount++
					return true
				}

				found := tb.ContainsFunc(predicate)

				if callCount != 1 {
					t.Fatalf("Expected predicate to be called once, but was called %d times", callCount)
				}

				return tb, predicate, found
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tb, predicate, want := tt.setupFunc(t)

			if tt.name == "stops iteration when predicate returns true" {
				return
			}

			got := tb.ContainsFunc(predicate)
			if got != want {
				t.Fatalf("ContainsFunc() = %v, want %v", got, want)
			}
		})
	}
}

// Helper functions

// testVerifySetup encapsulates common setup for verification tests.
type testVerifySetup struct {
	ca              *ekca.CA
	trustedBundle   TrustedBundle
	ekCert          *x509.Certificate
	rootPEM         []byte
	intermediatePEM []byte
}

// setupVerifyTest creates a complete test setup with CA, bundle and EK certificate.
func setupVerifyTest(t *testing.T, vendorID vendors.ID, includeIntermediate bool) *testVerifySetup {
	t.Helper()

	ca, rootPEM, intermediatePEM := createTestCABundle(t, vendorID)

	var tb TrustedBundle
	var err error
	if includeIntermediate {
		tb, err = newTrustedBundle(t.Context(), rootPEM, intermediatePEM)
	} else {
		tb, err = newTrustedBundle(t.Context(), rootPEM)
	}
	if err != nil {
		t.Fatalf("Failed to create trusted bundle: %v", err)
	}

	ekCert := generateEKCertificate(t, ca, vendorID)

	return &testVerifySetup{
		ca:              ca,
		trustedBundle:   tb,
		ekCert:          ekCert,
		rootPEM:         rootPEM,
		intermediatePEM: intermediatePEM,
	}
}

// formatBundleWithMetadata formats a certificate as a PEM bundle with vendor metadata.
func formatBundleWithMetadata(cert *x509.Certificate, vendorID vendors.ID, bundleType bundle.BundleType) []byte {
	var buf bytes.Buffer

	// Global bundle header
	date := time.Now().Format("2006-01-02")
	buf.WriteString(bundle.BuildBundleHeader("", date, "test-commit-hash", bundleType))

	// Certificate metadata
	certName := fmt.Sprintf("Test %s CA", vendorID)
	buf.WriteString(bundle.BuildCertificateHeader(cert, certName, string(vendorID)))

	// PEM-encoded certificate
	buf.Write(bundle.EncodePEM(cert))

	return buf.Bytes()
}

// createTestCABundle generates a test CA and formats it as PEM bundles with vendor metadata.
func createTestCABundle(t *testing.T, vendorID vendors.ID) (*ekca.CA, []byte, []byte) {
	t.Helper()

	ca, err := ekca.New(ekca.CAConfig{
		Root: &ekca.CertConfig{
			Subject: &pkix.Name{
				Organization: []string{"Test TPM Vendor"},
				CommonName:   fmt.Sprintf("%s Root CA", vendorID),
			},
		},
		Intermediate: &ekca.CertConfig{
			Subject: &pkix.Name{
				Organization: []string{"Test TPM Vendor"},
				CommonName:   fmt.Sprintf("%s Intermediate CA", vendorID),
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	rootPEM := formatBundleWithMetadata(ca.Root, vendorID, bundle.TypeRoot)
	intermediatePEM := formatBundleWithMetadata(ca.Intermediate, vendorID, bundle.TypeIntermediate)

	return ca, rootPEM, intermediatePEM
}

// generateEKCertificate generates an EK certificate signed by the given CA.
func generateEKCertificate(t *testing.T, ca *ekca.CA, vendorID vendors.ID) *x509.Certificate {
	t.Helper()

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	req := ekca.CertificateRequest{
		PublicKey: &ecdsaKey.PublicKey,
		NotAfter:  time.Now().Add(5 * time.Minute),
	}

	switch vendorID {
	case vendors.GOOG:
		req.SAN = &x509ext.SubjectAltName{
			TPMManufacturer: "id:474F4F47", // "GOOG" in hex
			TPMModel:        "test-model",
			TPMVersion:      "id:00000001",
		}
	case vendors.SNS:
		req.SAN = &x509ext.SubjectAltName{
			TPMManufacturer: "id:534E5300", // "SNS" in hex (padded)
			TPMModel:        "test-model",
			TPMVersion:      "id:00000001",
		}
	default:
		t.Fatalf("Unknown test vendor ID: %s", vendorID)
	}

	certDER, err := ca.GenerateCertificate(req)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}
