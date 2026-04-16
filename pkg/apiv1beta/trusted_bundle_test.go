package apiv1beta

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

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

func TestVerifyCertificate(t *testing.T) {
	t.Run("verifies valid Nuvoton EK certificate", func(t *testing.T) {
		// Skip test if TPM_EK_CERT_PATH is not set
		certPath := os.Getenv("TPM_EK_CERT_PATH")
		if certPath == "" {
			t.Skip("Skipping test: TPM_EK_CERT_PATH environment variable not set")
		}

		// Load bundle with Nuvoton vendor
		cfg := GetConfig{
			CachePath:  t.TempDir(),
			SkipVerify: true,
			VendorIDs:  []VendorID{NTC},
			AutoUpdate: AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		tb, err := GetTrustedBundle(t.Context(), cfg)
		if err != nil {
			t.Fatalf("Failed to get trusted bundle: %v", err)
		}
		defer tb.Stop()

		// Load test certificate from external file
		certPEM, err := utils.ReadFile(certPath)
		if err != nil {
			t.Fatalf("Failed to read EK certificate from %s: %v", certPath, err)
		}

		cert, err := testutil.ParseCertificate(certPEM)
		if err != nil {
			t.Fatalf("Failed to parse test certificate: %v", err)
		}

		// Verify the certificate
		if err := tb.Verify(cert); err != nil {
			t.Fatalf("Failed to verify certificate: %v", err)
		}
	})

	t.Run("verifies valid Nuvoton EK certificate without intermediates", func(t *testing.T) {
		// Skip test if TPM_EK_CERT_PATH is not set
		certPath := os.Getenv("TPM_EK_CERT_PATH")
		if certPath == "" {
			t.Skip("Skipping test: TPM_EK_CERT_PATH environment variable not set")
		}

		// Load bundle with Nuvoton vendor
		cfg := GetConfig{
			Date:       testutil.BundleVersion,
			CachePath:  t.TempDir(),
			SkipVerify: true,
			VendorIDs:  []VendorID{NTC},
			AutoUpdate: AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		tb, err := GetTrustedBundle(t.Context(), cfg)
		if err != nil {
			t.Fatalf("Failed to get trusted bundle: %v", err)
		}
		defer tb.Stop()

		// Load test certificate from external file
		certPEM, err := utils.ReadFile(certPath)
		if err != nil {
			t.Fatalf("Failed to read EK certificate from %s: %v", certPath, err)
		}

		cert, err := testutil.ParseCertificate(certPEM)
		if err != nil {
			t.Fatalf("Failed to parse test certificate: %v", err)
		}

		// Verify the certificate
		if err := tb.Verify(cert); err != nil {
			t.Fatalf("Failed to verify certificate: %v", err)
		}
	})

	t.Run("fails to verify certificate from untrusted vendor", func(t *testing.T) {
		// Skip test if TPM_EK_CERT_PATH is not set
		certPath := os.Getenv("TPM_EK_CERT_PATH")
		if certPath == "" {
			t.Skip("Skipping test: TPM_EK_CERT_PATH environment variable not set")
		}

		// Load bundle without Nuvoton vendor
		cfg := GetConfig{
			SkipVerify: true,
			VendorIDs:  []VendorID{IFX}, // Only Infineon
			AutoUpdate: AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
			CachePath: t.TempDir(),
		}

		tb, err := GetTrustedBundle(t.Context(), cfg)
		if err != nil {
			t.Fatalf("Failed to get trusted bundle: %v", err)
		}
		defer tb.Stop()

		// Load Nuvoton test certificate from external file
		certPEM, err := utils.ReadFile(certPath)
		if err != nil {
			t.Fatalf("Failed to read EK certificate from %s: %v", certPath, err)
		}

		cert, err := testutil.ParseCertificate(certPEM)
		if err != nil {
			t.Fatalf("Failed to parse test certificate: %v", err)
		}

		// Verification should fail
		if err := tb.Verify(cert); err == nil {
			t.Fatal("Expected verification to fail for certificate from untrusted vendor")
		}
	})
}

func TestContains(t *testing.T) {
	t.Run("returns true for certificate in root catalog", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		tbImpl := tb.(*trustedBundle)

		// Get a certificate from the root catalog
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

		if !tb.Contains(testCert) {
			t.Fatal("Expected Contains to return true for certificate in root catalog")
		}
	})

	t.Run("returns false for certificate not in bundle", func(t *testing.T) {
		// Skip test if TPM_EK_CERT_PATH is not set
		certPath := os.Getenv("TPM_EK_CERT_PATH")
		if certPath == "" {
			t.Skip("Skipping test: TPM_EK_CERT_PATH environment variable not set")
		}

		bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(t.Context(), bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		// Load a certificate that's not in the bundle
		certPEM, err := utils.ReadFile(certPath)
		if err != nil {
			t.Fatalf("Failed to read EK certificate from %s: %v", certPath, err)
		}

		cert, err := testutil.ParseCertificate(certPEM)
		if err != nil {
			t.Fatalf("Failed to parse test certificate: %v", err)
		}

		// This EK certificate should not be in the bundle (it's a leaf cert, not a root)
		if tb.Contains(cert) {
			t.Fatal("Expected Contains to return false for certificate not in bundle")
		}
	})

	t.Run("returns false for empty bundle", func(t *testing.T) {
		// Skip test if TPM_EK_CERT_PATH is not set
		certPath := os.Getenv("TPM_EK_CERT_PATH")
		if certPath == "" {
			t.Skip("Skipping test: TPM_EK_CERT_PATH environment variable not set")
		}

		tb := &trustedBundle{
			rootCatalog:         make(map[VendorID][]*x509.Certificate),
			intermediateCatalog: make(map[VendorID][]*x509.Certificate),
		}

		certPEM, err := utils.ReadFile(certPath)
		if err != nil {
			t.Fatalf("Failed to read EK certificate from %s: %v", certPath, err)
		}

		cert, err := testutil.ParseCertificate(certPEM)
		if err != nil {
			t.Fatalf("Failed to parse test certificate: %v", err)
		}

		if tb.Contains(cert) {
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

// func setupTrustedBundleWithRootCert(t *testing.T, selfSignedOnly bool) (TrustedBundle, *x509.Certificate) {
// 	t.Helper()

// 	bundleData, err := testutil.ReadTestFile(testutil.RootBundleFile)
// 	if err != nil {
// 		t.Fatalf("Failed to read test bundle: %v", err)
// 	}

// 	tb, err := newTrustedBundle(t.Context(), bundleData)
// 	if err != nil {
// 		t.Fatalf("Failed to create trusted bundle: %v", err)
// 	}

// 	tbImpl := tb.(*trustedBundle)
// 	var rootCert *x509.Certificate

// 	for _, certs := range tbImpl.rootCatalog {
// 		if len(certs) > 0 {
// 			if selfSignedOnly {
// 				for _, cert := range certs {
// 					if cert.Issuer.String() == cert.Subject.String() {
// 						rootCert = cert
// 						break
// 					}
// 				}
// 			} else {
// 				rootCert = certs[0]
// 			}
// 			if rootCert != nil {
// 				break
// 			}
// 		}
// 	}

// 	if rootCert == nil {
// 		if selfSignedOnly {
// 			t.Skip("No self-signed root certificates found in catalog")
// 		}
// 		t.Skip("No certificates found in root catalog")
// 	}

// 	return tb, rootCert
// }

// func TestVerifyWithOptionalChain(t *testing.T) {
// 	t.Run("verifies certificate with empty optional chain", func(t *testing.T) {
// 		tb, rootCert := setupTrustedBundleWithRootCert(t, true)

// 		errWithoutChain := tb.Verify(rootCert)
// 		errWithEmptyChain := tb.Verify(rootCert, []*x509.Certificate{})

// 		// Both should produce the same result
// 		if (errWithoutChain == nil) != (errWithEmptyChain == nil) {
// 			t.Fatalf("Expected same behavior with and without empty chain: without=%v, with=%v",
// 				errWithoutChain, errWithEmptyChain)
// 		}
// 	})

// 	t.Run("filters out root certificates from optional chain", func(t *testing.T) {
// 		tb, rootCert := setupTrustedBundleWithRootCert(t, true)

// 		errWithoutChain := tb.Verify(rootCert)
// 		errWithRootInChain := tb.Verify(rootCert, []*x509.Certificate{rootCert})

// 		// Self-signed certs should be filtered, so results should be identical
// 		if (errWithoutChain == nil) != (errWithRootInChain == nil) {
// 			t.Fatalf("Expected same behavior when self-signed cert is in optional chain: without=%v, with=%v",
// 				errWithoutChain, errWithRootInChain)
// 		}
// 	})

// 	t.Run("filters out certificates already in bundle from optional chain", func(t *testing.T) {
// 		tb, rootCert := setupTrustedBundleWithRootCert(t, false)

// 		errWithoutChain := tb.Verify(rootCert)
// 		errWithDuplicateInChain := tb.Verify(rootCert, []*x509.Certificate{rootCert})

// 		// Certs already in bundle should be filtered, so results should be identical
// 		if (errWithoutChain == nil) != (errWithDuplicateInChain == nil) {
// 			t.Fatalf("Expected same behavior when cert already in bundle is in optional chain: without=%v, with=%v",
// 				errWithoutChain, errWithDuplicateInChain)
// 		}
// 	})
// }

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
