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
	ctx := context.Background()

	t.Run("invalid vendor ID", func(t *testing.T) {
		cfg := GetConfig{
			SkipVerify: true,
			VendorIDs:  []VendorID{"INVALID_VENDOR"},
			AutoUpdate: AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		_, err := GetTrustedBundle(ctx, cfg)
		if err == nil {
			t.Fatal("Expected error for invalid vendor ID")
		}
	})
}

func TestPersist(t *testing.T) {
	t.Run("persist and verify files", func(t *testing.T) {
		tmpDir := t.TempDir()

		bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}
		tb.(*trustedBundle).vendorFilter = []VendorID{IFX}

		// Persist the bundle
		if err := tb.Persist(tmpDir); err != nil {
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
		bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		if err := tb.Persist(tmpDir); err != nil {
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
		bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(bundleData)
		if err != nil {
			t.Fatalf("Failed to create trusted bundle: %v", err)
		}

		vendors := tb.GetVendors()
		if len(vendors) == 0 {
			t.Fatal("Expected at least one vendor")
		}

		// Verify we get all vendors from the catalog
		tbImpl := tb.(*trustedBundle)
		if len(vendors) != len(tbImpl.catalog) {
			t.Fatalf("Expected %d vendors, got %d", len(tbImpl.catalog), len(vendors))
		}
	})

	t.Run("returns only filtered vendors with certificates", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(bundleData)
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
		bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(bundleData)
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
		bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		tb, err := newTrustedBundle(bundleData)
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
			catalog: make(map[VendorID][]*x509.Certificate),
		}

		vendors := tb.GetVendors()
		if len(vendors) != 0 {
			t.Fatalf("Expected 0 vendors, got %d", len(vendors))
		}
	})
}

func TestLoadOfflineMode(t *testing.T) {
	ctx := context.Background()

	t.Run("loads bundle successfully in offline mode", func(t *testing.T) {
		// Create cache with all required files including trusted-root.json
		cacheDir := testutil.CreateCacheDir(t, nil)

		// Load in offline mode
		tb, err := Load(ctx, LoadConfig{
			CachePath:   cacheDir,
			OfflineMode: true,
		})
		if err != nil {
			t.Fatalf("Failed to load bundle in offline mode: %v", err)
		}
		defer tb.Stop()

		// Verify bundle was loaded
		roots := tb.GetRoots()
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

		bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
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
		_, err = Load(ctx, LoadConfig{
			CachePath:   tmpDir,
			OfflineMode: true,
		})
		if err == nil {
			t.Fatal("Expected error when trusted-root.json is missing in offline mode")
		}
	})

	t.Run("fails when offline mode requires local cache", func(t *testing.T) {
		cacheDir := testutil.CreateCacheDir(t, nil)

		_, err := Load(ctx, LoadConfig{
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

		tb, err := Load(ctx, LoadConfig{
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
