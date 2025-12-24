package integration_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
)

func TestVerifyTrustedBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	t.Run("VerifyWithAutoDetectedMetadataAndDownloadedChecksums", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping integration test in short mode")
		}

		// First download a bundle
		trustedBundle, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
			Date:       testutil.BundleVersion,
			SkipVerify: true,
		})
		if err != nil {
			t.Fatalf("Failed to download bundle: %v", err)
		}

		// Now verify it with auto-detected metadata and auto-downloaded checksums
		_, err = apiv1beta.VerifyTrustedBundle(ctx, apiv1beta.VerifyConfig{
			Bundle: trustedBundle.GetRaw(),
		})
		if err != nil {
			t.Fatalf("Verification failed: %v", err)
		}
	})

	t.Run("EmptyBundleError", func(t *testing.T) {
		_, err := apiv1beta.VerifyTrustedBundle(ctx, apiv1beta.VerifyConfig{
			Bundle: []byte{},
		})
		if err == nil {
			t.Fatal("Expected error for empty bundle")
		}

		if !strings.Contains(err.Error(), "bundle cannot be empty") {
			t.Errorf("Expected 'bundle cannot be empty' error, got: %v", err)
		}
	})

	t.Run("InvalidBundleMetadata", func(t *testing.T) {
		// Bundle with metadata that has Date but no Commit
		_, err := apiv1beta.VerifyTrustedBundle(ctx, apiv1beta.VerifyConfig{
			Bundle: []byte("dummy"),
			BundleMetadata: &bundle.Metadata{
				Date:   testutil.BundleVersion,
				Commit: "", // Empty commit should fail validation
			},
		})
		if err == nil {
			t.Fatal("Expected error when BundleMetadata has empty Commit")
		}

		if !strings.Contains(err.Error(), "metadata 'Commit' is required") {
			t.Errorf("Expected validation error about commit, got: %v", err)
		}
	})

	t.Run("InvalidBundleContent", func(t *testing.T) {
		// Bundle without proper metadata headers should fail parsing
		_, err := apiv1beta.VerifyTrustedBundle(ctx, apiv1beta.VerifyConfig{
			Bundle: []byte("invalid bundle content without metadata"),
		})
		if err == nil {
			t.Fatal("Expected error when bundle has no valid metadata")
		}

		if !strings.Contains(err.Error(), "failed to parse bundle metadata") {
			t.Errorf("Expected metadata parsing error, got: %v", err)
		}
	})
}

func TestGetTrustedBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	t.Parallel()

	t.Run("fetch and parse latest bundle", func(t *testing.T) {
		cfg := apiv1beta.GetConfig{
			SkipVerify: true,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
			CachePath: t.TempDir(),
		}

		tb, err := apiv1beta.GetTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("GetTrustedBundle() error = %v", err)
		}
		defer tb.Stop()

		metadata := tb.GetMetadata()
		if metadata == nil {
			t.Fatal("Expected metadata, got nil")
		}
		if metadata.Date == "" {
			t.Error("Expected date in metadata")
		}
		if metadata.Commit == "" {
			t.Error("Expected commit in metadata")
		}

		vendors := tb.GetVendors()
		if len(vendors) == 0 {
			t.Error("Expected at least one vendor")
		}

		certPool := tb.GetRoots()
		if certPool == nil {
			t.Fatal("Expected cert pool, got nil")
		}

		raw := tb.GetRaw()
		certs, err := parsePEMCertificates(raw)
		if err != nil {
			t.Fatalf("Failed to parse PEM certificates: %v", err)
		}
		if len(certs) == 0 {
			t.Error("Expected at least one certificate in raw bundle")
		}
	})

	t.Run("fetch specific date with verification", func(t *testing.T) {
		cfg := apiv1beta.GetConfig{
			Date: testutil.BundleVersion,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
			CachePath: t.TempDir(),
		}

		tb, err := apiv1beta.GetTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("GetTrustedBundle() error = %v", err)
		}

		metadata := tb.GetMetadata()
		if metadata.Date != testutil.BundleVersion {
			t.Errorf("Expected date '2025-12-05', got %q", metadata.Date)
		}
	})

	t.Run("stop is idempotent", func(t *testing.T) {
		cfg := apiv1beta.GetConfig{
			SkipVerify: true,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
			CachePath: t.TempDir(),
		}

		tb, err := apiv1beta.GetTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("GetTrustedBundle() error = %v", err)
		}

		// Call Stop multiple times
		if err := tb.Stop(); err != nil {
			t.Errorf("First Stop() error = %v", err)
		}
		if err := tb.Stop(); err != nil {
			t.Errorf("Second Stop() error = %v", err)
		}
	})

	t.Run("fetch latest bundle without verification", func(t *testing.T) {
		cfg := apiv1beta.GetConfig{
			SkipVerify: true,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
			CachePath: t.TempDir(),
		}

		tb, err := apiv1beta.GetTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("GetTrustedBundle() error = %v", err)
		}

		metadata := tb.GetMetadata()
		if metadata == nil {
			t.Fatal("Expected metadata, got nil")
		}
		if metadata.Date == "" {
			t.Error("Expected date in metadata")
		}
		if metadata.Commit == "" {
			t.Error("Expected commit in metadata")
		}

		raw := tb.GetRaw()
		if len(raw) == 0 {
			t.Error("Expected raw bundle, got empty")
		}

		// Check vendors
		vendors := tb.GetVendors()
		if len(vendors) == 0 {
			t.Error("Expected at least one vendor")
		}

		// Check cert pool
		certPool := tb.GetRoots()
		if certPool == nil {
			t.Fatal("Expected cert pool, got nil")
		}
	})

	t.Run("filter by vendor IDs", func(t *testing.T) {
		cfg := apiv1beta.GetConfig{
			SkipVerify: true,
			VendorIDs:  []apiv1beta.VendorID{apiv1beta.NTC, apiv1beta.IFX},
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
			CachePath: t.TempDir(),
		}

		tb, err := apiv1beta.GetTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("GetTrustedBundle() error = %v", err)
		}

		// Verify that the bundle contains all vendors (not filtered at fetch time)
		allVendors := tb.GetVendors()
		if len(allVendors) != 2 {
			t.Errorf("Expected 2 vendors in catalog, got %d", len(allVendors))
		}
	})

	t.Run("auto-update refreshes to newer version", func(t *testing.T) {
		// Start with an older version (2025-12-03)
		cfg := apiv1beta.GetConfig{
			Date:       "2025-12-03",
			SkipVerify: true,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				Interval: 2 * time.Second, // Short interval for testing
			},
			CachePath: t.TempDir(),
		}

		tb, err := apiv1beta.GetTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("GetTrustedBundle() error = %v", err)
		}
		defer tb.Stop()

		// Verify initial version
		initialMetadata := tb.GetMetadata()
		if initialMetadata.Date != "2025-12-03" {
			t.Errorf("Expected initial date '2025-12-03', got %q", initialMetadata.Date)
		}
		t.Logf("Initial bundle date: %s", initialMetadata.Date)

		// Wait for auto-update to trigger (interval + some buffer)
		time.Sleep(3 * time.Second)

		// Check if bundle was updated to latest version (2025-12-05)
		updatedMetadata := tb.GetMetadata()
		t.Logf("Updated bundle date: %s", updatedMetadata.Date)

		if updatedMetadata.Date == "2025-12-03" {
			t.Error("Bundle was not auto-updated after interval")
		}

		// The bundle should now be at the latest version (2025-12-05 or newer)
		if updatedMetadata.Date < testutil.BundleVersion {
			t.Errorf("Expected bundle to update to at least '2025-12-05', got %q", updatedMetadata.Date)
		}

		// Verify commit also changed
		if updatedMetadata.Commit == initialMetadata.Commit {
			t.Error("Expected commit to change after update")
		}
	})
}

func TestTrustedBundle_ThreadSafety(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping thread safety test in short mode")
	}

	ctx := context.Background()
	cfg := apiv1beta.GetConfig{
		SkipVerify: true,
		AutoUpdate: apiv1beta.AutoUpdateConfig{
			DisableAutoUpdate: true,
		},
	}

	tb, err := apiv1beta.GetTrustedBundle(ctx, cfg)
	if err != nil {
		t.Fatalf("GetTrustedBundle() error = %v", err)
	}

	// Concurrently call all methods
	done := make(chan bool)
	for range 10 {
		go func() {
			for range 100 {
				_ = tb.GetRaw()
				_ = tb.GetMetadata()
				_ = tb.GetVendors()
				_ = tb.GetRoots()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for range 10 {
		<-done
	}
}

func parsePEMCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData

	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

func TestSmartCache(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	t.Run("first fetch downloads and caches bundle", func(t *testing.T) {
		tmpDir := t.TempDir()

		// First call should download from GitHub and cache
		cfg := apiv1beta.GetConfig{
			Date:       testutil.BundleVersion,
			SkipVerify: true,
			CachePath:  tmpDir,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		tb, err := apiv1beta.GetTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("First GetTrustedBundle() error = %v", err)
		}
		defer tb.Stop()

		// Verify cache was created
		configPath := filepath.Join(tmpDir, apiv1beta.CacheConfigFilename)
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			t.Fatal("Cache config.json was not created")
		}

		bundlePath := filepath.Join(tmpDir, apiv1beta.CacheRootBundleFilename)
		if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
			t.Fatal("Cache bundle was not created")
		}

		// Verify config contains correct version
		configData, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config: %v", err)
		}

		var cacheConfig apiv1beta.CacheConfig
		if err := json.Unmarshal(configData, &cacheConfig); err != nil {
			t.Fatalf("Failed to unmarshal config: %v", err)
		}

		if cacheConfig.Version != testutil.BundleVersion {
			t.Errorf("Expected version '2025-12-05', got %q", cacheConfig.Version)
		}
	})

	t.Run("second fetch uses cache", func(t *testing.T) {
		tmpDir := t.TempDir()

		// First call to populate cache
		cfg1 := apiv1beta.GetConfig{
			Date:       testutil.BundleVersion,
			SkipVerify: true,
			CachePath:  tmpDir,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		tb1, err := apiv1beta.GetTrustedBundle(ctx, cfg1)
		if err != nil {
			t.Fatalf("First GetTrustedBundle() error = %v", err)
		}
		tb1.Stop()

		// Get modification time of bundle file
		bundlePath := filepath.Join(tmpDir, apiv1beta.CacheRootBundleFilename)
		info1, err := os.Stat(bundlePath)
		if err != nil {
			t.Fatalf("Failed to stat bundle: %v", err)
		}
		modTime1 := info1.ModTime()

		// Wait a bit to ensure modification time would differ if file was rewritten
		time.Sleep(10 * time.Millisecond)

		// Second call with same config should use cache
		cfg2 := apiv1beta.GetConfig{
			Date:       testutil.BundleVersion,
			SkipVerify: true,
			CachePath:  tmpDir,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		tb2, err := apiv1beta.GetTrustedBundle(ctx, cfg2)
		if err != nil {
			t.Fatalf("Second GetTrustedBundle() error = %v", err)
		}
		defer tb2.Stop()

		// Verify bundle file was not modified (loaded from cache)
		info2, err := os.Stat(bundlePath)
		if err != nil {
			t.Fatalf("Failed to stat bundle after second call: %v", err)
		}
		modTime2 := info2.ModTime()

		if !modTime1.Equal(modTime2) {
			t.Error("Bundle file was modified, expected it to be loaded from cache")
		}

		// Verify bundle content is the same
		if string(tb1.GetRaw()) != string(tb2.GetRaw()) {
			t.Error("Bundle content differs between first and second fetch")
		}
	})

	t.Run("different version triggers new download", func(t *testing.T) {
		tmpDir := t.TempDir()

		// First call with version 2025-12-05
		cfg1 := apiv1beta.GetConfig{
			Date:       testutil.BundleVersion,
			SkipVerify: true,
			CachePath:  tmpDir,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		tb1, err := apiv1beta.GetTrustedBundle(ctx, cfg1)
		if err != nil {
			t.Fatalf("First GetTrustedBundle() error = %v", err)
		}
		tb1.Stop()

		// Second call with different version should download again
		cfg2 := apiv1beta.GetConfig{
			Date:       "2025-12-03",
			SkipVerify: true,
			CachePath:  tmpDir,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		tb2, err := apiv1beta.GetTrustedBundle(ctx, cfg2)
		if err != nil {
			t.Fatalf("Second GetTrustedBundle() error = %v", err)
		}
		defer tb2.Stop()

		// Verify cache now contains the new version
		configPath := filepath.Join(tmpDir, apiv1beta.CacheConfigFilename)
		configData, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("Failed to read config: %v", err)
		}

		var cacheConfig apiv1beta.CacheConfig
		if err := json.Unmarshal(configData, &cacheConfig); err != nil {
			t.Fatalf("Failed to unmarshal config: %v", err)
		}

		if cacheConfig.Version != "2025-12-03" {
			t.Errorf("Expected version '2025-12-03', got %q", cacheConfig.Version)
		}

		// Verify bundle metadata
		metadata := tb2.GetMetadata()
		if metadata.Date != "2025-12-03" {
			t.Errorf("Expected bundle date '2025-12-03', got %q", metadata.Date)
		}
	})

	t.Run("DisableLocalCache bypasses cache", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Call with DisableLocalCache=true should not create cache
		cfg := apiv1beta.GetConfig{
			Date:              testutil.BundleVersion,
			SkipVerify:        true,
			CachePath:         tmpDir,
			DisableLocalCache: true,
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		tb, err := apiv1beta.GetTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("GetTrustedBundle() error = %v", err)
		}
		defer tb.Stop()

		// Verify cache was NOT created
		configPath := filepath.Join(tmpDir, apiv1beta.CacheConfigFilename)
		if _, err := os.Stat(configPath); !os.IsNotExist(err) {
			t.Error("Cache config.json should not exist when DisableLocalCache is true")
		}
	})
}

func TestLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Parallel()

	ctx := context.Background()
	// cfg := apiv1beta.CacheConfig{
	// 	Version:       testutil.BundleVersion,
	// 	AutoUpdate:    &apiv1beta.AutoUpdateConfig{},
	// 	VendorIDs:     []apiv1beta.VendorID{apiv1beta.IFX},
	// 	LastTimestamp: time.Now(),
	// }
	// configData, err := json.Marshal(cfg)
	// if err != nil {
	// 	t.Fatalf("Failed to marshal config: %v", err)
	// }

	// t.Run("load from cache without network requests", func(t *testing.T) {
	// 	tmpDir := testutil.CreateCacheDir(t, configData)

	// 	tb, err := apiv1beta.Load(ctx, apiv1beta.LoadConfig{
	// 		CachePath:  tmpDir,
	// 		SkipVerify: false,
	// 	})
	// 	if err != nil {
	// 		t.Fatalf("Load failed: %v", err)
	// 	}
	// 	defer tb.Stop()

	// 	// Verify the loaded bundle
	// 	metadata := tb.GetMetadata()
	// 	if metadata.Date == "" {
	// 		t.Error("Metadata date is empty")
	// 	}
	// 	if metadata.Commit == "" {
	// 		t.Error("Metadata commit is empty")
	// 	}

	// 	vendors := tb.GetVendors()
	// 	if len(vendors) != 1 {
	// 		t.Errorf("Expected 1 vendor, got %d", len(vendors))
	// 	}
	// })

	// t.Run("load fails if provenance is missing", func(t *testing.T) {
	// 	tmpDir := testutil.CreateCacheDir(t, configData)

	// 	// Intentionally remove provenance file
	// 	if err := os.Remove(filepath.Join(tmpDir, apiv1beta.CacheProvenanceFilename)); err != nil {
	// 		t.Fatalf("Failed to remove provenance file: %v", err)
	// 	}

	// 	// Load should fail because provenance is missing
	// 	_, err := apiv1beta.Load(ctx, apiv1beta.LoadConfig{
	// 		CachePath:  tmpDir,
	// 		SkipVerify: false,
	// 	})
	// 	if err == nil {
	// 		t.Fatal("Expected Load to fail with missing provenance, but it succeeded")
	// 	}
	// 	expectedErrMsg := "failed to read provenance"
	// 	if !strings.Contains(err.Error(), expectedErrMsg) {
	// 		t.Errorf("Expected error message to contain %q, got: %v", expectedErrMsg, err)
	// 	}
	// })

	// t.Run("load with missing cache directory", func(t *testing.T) {
	// 	_, err := apiv1beta.Load(ctx, apiv1beta.LoadConfig{
	// 		CachePath: "/nonexistent/directory",
	// 	})
	// 	if err == nil {
	// 		t.Fatal("Expected error for missing cache directory")
	// 	}
	// 	expectedErrMsg := "cache directory does not exist"
	// 	if !strings.Contains(err.Error(), expectedErrMsg) {
	// 		t.Errorf("Expected error message to contain %q, got: %v", expectedErrMsg, err)
	// 	}
	// })

	t.Run("auto-update after load refreshes to newer version", func(t *testing.T) {
		// Create cache config with auto-update enabled and short interval
		cfg := apiv1beta.CacheConfig{
			Version: testutil.BundleVersion,
			AutoUpdate: &apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: false,
				Interval:          2 * time.Second,
			},
			VendorIDs:     []apiv1beta.VendorID{apiv1beta.IFX},
			LastTimestamp: time.Now(),
		}
		configData, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("Failed to marshal config: %v", err)
		}

		tmpDir := testutil.CreateCacheDir(t, configData)

		// Load the bundle from cache (old version)
		tb, err := apiv1beta.Load(ctx, apiv1beta.LoadConfig{
			CachePath:  tmpDir,
			SkipVerify: true,
		})
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer tb.Stop()

		initialMetadata := tb.GetMetadata()
		t.Logf("Initial bundle date after load: %s", initialMetadata.Date)

		// The cached bundle is older, so we expect it to be updated
		// Wait for auto-update to trigger (interval + buffer)
		time.Sleep(3 * time.Second)

		updatedMetadata := tb.GetMetadata()
		t.Logf("Updated bundle date after auto-update: %s", updatedMetadata.Date)

		if updatedMetadata.Date == initialMetadata.Date {
			t.Error("Bundle was not auto-updated after interval")
		}

		if updatedMetadata.Commit == initialMetadata.Commit {
			t.Error("Expected commit to change after update")
		}

		newConfigData, err := utils.ReadFile(filepath.Join(tmpDir, apiv1beta.CacheConfigFilename))
		if err != nil {
			t.Fatalf("Failed to read updated config: %v", err)
		}

		var newCfg apiv1beta.CacheConfig
		if err := json.Unmarshal(newConfigData, &newCfg); err != nil {
			t.Fatalf("Failed to unmarshal updated config: %v", err)
		}

		if newCfg.Version != updatedMetadata.Date {
			t.Errorf("Expected config version %q to match updated metadata date %q", newCfg.Version, updatedMetadata.Date)
		}
		if !reflect.DeepEqual(cfg.AutoUpdate, newCfg.AutoUpdate) {
			t.Errorf("Expected auto-update config to be unchanged")
		}
		if !slices.Equal(cfg.VendorIDs, newCfg.VendorIDs) {
			t.Errorf("Expected vendor IDs to be unchanged")
		}
		if !newCfg.LastTimestamp.After(cfg.LastTimestamp) {
			t.Errorf("Expected LastTimestamp to be updated")
		}
	})
}

func TestSave(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	t.Parallel()

	t.Run("save bundle with all verification assets", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Save the latest bundle
		resp, err := apiv1beta.Save(ctx, apiv1beta.SaveConfig{
			CachePath: tmpDir,
		})
		if err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		// Verify SaveResponse contains all required assets
		if len(resp.RootBundle) == 0 {
			t.Error("Expected RootBundle to be populated")
		}
		if len(resp.RootProvenance) == 0 {
			t.Error("Expected RootProvenance to be populated")
		}
		if len(resp.Checksum) == 0 {
			t.Error("Expected Checksum to be populated")
		}
		if len(resp.ChecksumSignature) == 0 {
			t.Error("Expected ChecksumSignature to be populated")
		}
		if len(resp.TrustedRoot) == 0 {
			t.Error("Expected TrustedRoot to be populated")
		}
		if len(resp.CacheConfig) == 0 {
			t.Error("Expected CacheConfig to be populated")
		}

		// Verify IntermediateBundle and IntermediateProvenance are empty (out of scope)
		if len(resp.IntermediateBundle) != 0 {
			t.Error("Expected IntermediateBundle to be empty (out of scope)")
		}
		if len(resp.IntermediateProvenance) != 0 {
			t.Error("Expected IntermediateProvenance to be empty (out of scope)")
		}

		// Verify CacheConfig can be unmarshaled
		var cacheConfig apiv1beta.CacheConfig
		if err := json.Unmarshal(resp.CacheConfig, &cacheConfig); err != nil {
			t.Fatalf("Failed to unmarshal CacheConfig: %v", err)
		}

		if cacheConfig.Version == "" {
			t.Error("Expected CacheConfig.Version to be populated")
		}
		if cacheConfig.SkipVerify {
			t.Error("Expected CacheConfig.SkipVerify to be false")
		}
	})

	t.Run("save specific date with vendor filter", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Save a specific date with vendor filter
		resp, err := apiv1beta.Save(ctx, apiv1beta.SaveConfig{
			Date:      testutil.BundleVersion,
			VendorIDs: []apiv1beta.VendorID{apiv1beta.IFX, apiv1beta.NTC},
			CachePath: tmpDir,
		})
		if err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		// Verify CacheConfig contains vendor filter
		var cacheConfig apiv1beta.CacheConfig
		if err := json.Unmarshal(resp.CacheConfig, &cacheConfig); err != nil {
			t.Fatalf("Failed to unmarshal CacheConfig: %v", err)
		}

		if cacheConfig.Version != testutil.BundleVersion {
			t.Errorf("Expected version %q, got %q", testutil.BundleVersion, cacheConfig.Version)
		}

		if len(cacheConfig.VendorIDs) != 2 {
			t.Errorf("Expected 2 vendor IDs, got %d", len(cacheConfig.VendorIDs))
		}
	})

	t.Run("persist saves all files to output directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Save and persist
		resp, err := apiv1beta.Save(ctx, apiv1beta.SaveConfig{
			Date:      testutil.BundleVersion,
			CachePath: tmpDir,
		})
		if err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		outputDir := t.TempDir()
		if err := resp.Persist(outputDir); err != nil {
			t.Fatalf("Persist() error = %v", err)
		}

		// Verify all files were created
		for _, filename := range apiv1beta.CacheFilenames {
			filePath := filepath.Join(outputDir, filename)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Errorf("Expected file %q to exist", filename)
			}
		}

		// Verify file contents match response
		bundleData, err := os.ReadFile(filepath.Join(outputDir, apiv1beta.CacheRootBundleFilename))
		if err != nil {
			t.Fatalf("Failed to read bundle file: %v", err)
		}
		if !slices.Equal(bundleData, resp.RootBundle) {
			t.Error("Bundle file content doesn't match response")
		}

		trustedRootData, err := os.ReadFile(filepath.Join(outputDir, apiv1beta.CacheTrustedRootFilename))
		if err != nil {
			t.Fatalf("Failed to read trusted root file: %v", err)
		}
		if !slices.Equal(trustedRootData, resp.TrustedRoot) {
			t.Error("Trusted root file content doesn't match response")
		}

		// Verify trusted-root.json is valid JSON
		var trustedRootJSON map[string]any
		if err := json.Unmarshal(trustedRootData, &trustedRootJSON); err != nil {
			t.Errorf("Trusted root is not valid JSON: %v", err)
		}
	})

	t.Run("save and load for offline verification", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Save bundle
		resp, err := apiv1beta.Save(ctx, apiv1beta.SaveConfig{
			Date:      testutil.BundleVersion,
			CachePath: tmpDir,
		})
		if err != nil {
			t.Fatalf("Save() error = %v", err)
		}

		// Persist to cache directory
		cacheDir := t.TempDir()
		if err := resp.Persist(cacheDir); err != nil {
			t.Fatalf("Persist() error = %v", err)
		}

		// Load the saved bundle from cache
		tb, err := apiv1beta.Load(ctx, apiv1beta.LoadConfig{
			CachePath:  cacheDir,
			SkipVerify: false, // Verify using cached assets
		})
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		defer tb.Stop()

		// Verify the loaded bundle
		metadata := tb.GetMetadata()
		if metadata.Date != testutil.BundleVersion {
			t.Errorf("Expected date %q, got %q", testutil.BundleVersion, metadata.Date)
		}

		// Verify we can get roots
		certPool := tb.GetRoots()
		if certPool == nil {
			t.Error("Expected cert pool, got nil")
		}
	})
}
