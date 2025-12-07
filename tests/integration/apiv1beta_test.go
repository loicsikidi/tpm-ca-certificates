package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
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
			Date:       "2025-12-05",
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
				Date:   "2025-12-05",
				Commit: "", // Empty commit should fail validation
			},
		})
		if err == nil {
			t.Fatal("Expected error when BundleMetadata has empty Commit")
		}

		if !strings.Contains(err.Error(), "commit cannot be empty") {
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

	t.Run("fetch and parse latest bundle", func(t *testing.T) {
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
		if len(certs) == 1 {
			t.Errorf("Expected 1 certificates in the bundle, got %d", len(certs))
		}
	})

	t.Run("fetch specific date with verification", func(t *testing.T) {
		cfg := apiv1beta.GetConfig{
			Date: "2025-12-05",
			AutoUpdate: apiv1beta.AutoUpdateConfig{
				DisableAutoUpdate: true,
			},
		}

		tb, err := apiv1beta.GetTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("GetTrustedBundle() error = %v", err)
		}

		metadata := tb.GetMetadata()
		if metadata.Date != "2025-12-05" {
			t.Errorf("Expected date '2025-12-05', got %q", metadata.Date)
		}
	})

	t.Run("stop is idempotent", func(t *testing.T) {
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
		}

		tb, err := apiv1beta.GetTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("GetTrustedBundle() error = %v", err)
		}

		// Verify that the bundle contains all vendors (not filtered at fetch time)
		allVendors := tb.GetVendors()
		if len(allVendors) < 2 {
			t.Errorf("Expected at least 2 vendors in catalog, got %d", len(allVendors))
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
		if updatedMetadata.Date < "2025-12-05" {
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
