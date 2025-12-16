package apiv1beta

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
)

func TestCheckCacheExists(t *testing.T) {
	t.Run("returns false when cache directory does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()
		nonExistentPath := filepath.Join(tmpDir, "nonexistent")

		if checkCacheExists(nonExistentPath, "2025-12-15") {
			t.Fatal("Expected checkCacheExists to return false for non-existent directory")
		}
	})

	t.Run("returns false when config.json does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()

		if checkCacheExists(tmpDir, "2025-12-15") {
			t.Fatal("Expected checkCacheExists to return false when config.json does not exist")
		}
	})

	t.Run("returns false when version does not match", func(t *testing.T) {
		// Create config with different version
		cfg := CacheConfig{
			Version: testutil.BundleVersion,
		}
		configData, _ := json.Marshal(cfg)
		tmpDir := testutil.CreateCacheDir(t, configData)

		if checkCacheExists(tmpDir, "2025-01-01") {
			t.Fatal("Expected checkCacheExists to return false when version does not match")
		}
	})

	t.Run("returns false when missing at least one verification asset", func(t *testing.T) {
		// Create config with different version
		cfg := CacheConfig{
			Version: testutil.BundleVersion,
		}
		configData, _ := json.Marshal(cfg)
		tmpDir := testutil.CreateCacheDir(t, configData)

		if err := os.Remove(filepath.Join(tmpDir, CacheChecksumsFilename)); err != nil {
			t.Fatalf("Failed to remove checksum file: %v", err)
		}

		if checkCacheExists(tmpDir, testutil.BundleVersion) {
			t.Fatal("Expected checkCacheExists to return false when verification asset is missing")
		}
	})

	t.Run("returns true when just config.json and bundle exists when skipVerify is true", func(t *testing.T) {
		tmpDir := t.TempDir()

		cfg := CacheConfig{
			Version:    testutil.BundleVersion,
			SkipVerify: true,
		}
		configData, _ := json.Marshal(cfg)
		configPath := filepath.Join(tmpDir, CacheConfigFilename)
		os.WriteFile(configPath, configData, 0644)

		bundlePath := filepath.Join(tmpDir, CacheRootBundleFilename)
		os.WriteFile(bundlePath, []byte("test bundle"), 0644)

		if !checkCacheExists(tmpDir, testutil.BundleVersion) {
			t.Fatal("Expected checkCacheExists to return true")
		}
	})

	t.Run("returns true when everything is present", func(t *testing.T) {
		cfg := CacheConfig{
			Version: testutil.BundleVersion,
		}
		configData, _ := json.Marshal(cfg)
		tmpDir := testutil.CreateCacheDir(t, configData)

		if !checkCacheExists(tmpDir, testutil.BundleVersion) {
			t.Fatal("Expected checkCacheExists to return true")
		}
	})
}

func TestGetBundleFromCache(t *testing.T) {
	t.Run("loads bundle and verification assets", func(t *testing.T) {
		cfg := CacheConfig{
			Version: testutil.BundleVersion,
		}
		configData, _ := json.Marshal(cfg)
		tmpDir := testutil.CreateCacheDir(t, configData)

		// Load from cache
		result, err := getBundleFromCache(tmpDir, false)
		if err != nil {
			t.Fatalf("Failed to load from cache: %v", err)
		}

		if len(result.bundleData) == 0 {
			t.Fatal("Bundle data is empty")
		}
		if len(result.checksum) == 0 {
			t.Fatal("checksum data is empty")
		}
		if len(result.checksumSignature) == 0 {
			t.Fatal("checksumSignature data is empty")
		}
		if len(result.provenance) == 0 {
			t.Fatal("provenance data is empty")
		}
	})

	t.Run("skips verification assets when skipVerify is true", func(t *testing.T) {
		cfg := CacheConfig{
			Version: testutil.BundleVersion,
		}
		configData, _ := json.Marshal(cfg)
		tmpDir := testutil.CreateCacheDir(t, configData)

		// Load from cache with skipVerify
		result, err := getBundleFromCache(tmpDir, true)
		if err != nil {
			t.Fatalf("Failed to load from cache: %v", err)
		}

		if len(result.bundleData) == 0 {
			t.Fatal("Bundle data is empty")
		}
		if len(result.checksum) != 0 {
			t.Fatal("Expected checksum to be empty when skipVerify is true")
		}
		if len(result.checksumSignature) != 0 {
			t.Fatal("Expected checksum signature to be empty when skipVerify is true")
		}
		if len(result.provenance) != 0 {
			t.Fatal("Expected provenance to be empty when skipVerify is true")
		}
	})

	t.Run("returns error when bundle file does not exist", func(t *testing.T) {
		tmpDir := t.TempDir()

		_, err := getBundleFromCache(tmpDir, false)
		if err == nil {
			t.Fatal("Expected error when bundle file does not exist")
		}
	})

	t.Run("returns error when verification asset is missing and skipVerify is false", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Read test bundle
		bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		// Create bundle file only
		bundlePath := filepath.Join(tmpDir, CacheRootBundleFilename)
		if err := os.WriteFile(bundlePath, bundleData, 0644); err != nil {
			t.Fatalf("Failed to write bundle: %v", err)
		}

		// Try to load without verification assets
		_, err = getBundleFromCache(tmpDir, false)
		if err == nil {
			t.Fatal("Expected error when verification assets are missing")
		}
	})
}

func TestCacheConfigValidation(t *testing.T) {
	t.Run("CheckAndSetDefaults returns error when version is empty", func(t *testing.T) {
		cfg := CacheConfig{
			Version: "",
		}

		err := cfg.CheckAndSetDefaults()
		if err == nil {
			t.Fatal("Expected error when version is empty")
		}
	})

	t.Run("CheckAndSetDefaults succeeds with valid version", func(t *testing.T) {
		cfg := CacheConfig{
			Version:    "2025-12-15",
			AutoUpdate: &AutoUpdateConfig{DisableAutoUpdate: true},
		}

		err := cfg.CheckAndSetDefaults()
		if err != nil {
			t.Fatalf("Expected no error with valid config: %v", err)
		}
	})
}
