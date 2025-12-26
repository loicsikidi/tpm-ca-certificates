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
		assetsCfg := assetsConfig{
			cachePath:                 tmpDir,
			downloadChecksums:         true,
			downloadChecksumSignature: true,
			downloadProvenance:        true,
		}
		result, err := getAssetsFromCache(assetsCfg)
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

	t.Run("filter assets to avoid verification artefacts", func(t *testing.T) {
		cfg := CacheConfig{
			Version: testutil.BundleVersion,
		}
		configData, _ := json.Marshal(cfg)
		tmpDir := testutil.CreateCacheDir(t, configData)

		// Load from cache with
		assetsCfg := assetsConfig{
			cachePath: tmpDir,
		}
		result, err := getAssetsFromCache(assetsCfg)
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

		assetsCfg := assetsConfig{
			cachePath:                 tmpDir,
			downloadChecksums:         true,
			downloadChecksumSignature: true,
			downloadProvenance:        true,
		}
		_, err := getAssetsFromCache(assetsCfg)
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
		assetsCfg := assetsConfig{
			cachePath:                 tmpDir,
			downloadChecksums:         true,
			downloadChecksumSignature: true,
			downloadProvenance:        true,
		}
		_, err = getAssetsFromCache(assetsCfg)
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

func TestVerifyTrustedBundleWithCustomTrustedRoot(t *testing.T) {

	t.Run("verifies bundle with custom trusted root", func(t *testing.T) {
		// Load all required test data
		bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		checksumData, err := testutil.ReadTestFile(testutil.ChecksumFile)
		if err != nil {
			t.Fatalf("Failed to read checksums: %v", err)
		}

		checksumSigData, err := testutil.ReadTestFile(testutil.ChecksumSigstoreFile)
		if err != nil {
			t.Fatalf("Failed to read checksum signature: %v", err)
		}

		provenanceData, err := testutil.ReadTestFile(testutil.ProvenanceFile)
		if err != nil {
			t.Fatalf("Failed to read provenance: %v", err)
		}

		trustedRootData, err := testutil.ReadTestFile(testutil.TrustedRootFile)
		if err != nil {
			t.Fatalf("Failed to read trusted root: %v", err)
		}

		// Verify with custom trusted root (offline mode)
		result, err := VerifyTrustedBundle(t.Context(), VerifyConfig{
			Bundle:            bundleData,
			Checksum:          checksumData,
			ChecksumSignature: checksumSigData,
			Provenance:        provenanceData,
			TrustedRoot:       trustedRootData,
		})
		if err != nil {
			t.Fatalf("Failed to verify bundle with custom trusted root: %v", err)
		}

		if result == nil {
			t.Fatal("Expected verification result to be non-nil")
		}
		if result.CosignResult == nil {
			t.Fatal("Expected Cosign result to be non-nil")
		}
		if len(result.GithubAttestationResults) == 0 {
			t.Fatal("Expected at least one GitHub attestation result")
		}
	})

	t.Run("fails with invalid trusted root JSON", func(t *testing.T) {
		bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
		if err != nil {
			t.Fatalf("Failed to read test bundle: %v", err)
		}

		checksumData, err := testutil.ReadTestFile(testutil.ChecksumFile)
		if err != nil {
			t.Fatalf("Failed to read checksums: %v", err)
		}

		checksumSigData, err := testutil.ReadTestFile(testutil.ChecksumSigstoreFile)
		if err != nil {
			t.Fatalf("Failed to read checksum signature: %v", err)
		}

		provenanceData, err := testutil.ReadTestFile(testutil.ProvenanceFile)
		if err != nil {
			t.Fatalf("Failed to read provenance: %v", err)
		}

		// Try to verify with invalid JSON
		_, err = VerifyTrustedBundle(t.Context(), VerifyConfig{
			Bundle:            bundleData,
			Checksum:          checksumData,
			ChecksumSignature: checksumSigData,
			Provenance:        provenanceData,
			TrustedRoot:       []byte("invalid json"),
		})
		if err == nil {
			t.Fatal("Expected error with invalid trusted root JSON")
		}
	})
}
