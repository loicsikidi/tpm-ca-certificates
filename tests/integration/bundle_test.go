package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/api"
)

func TestGetRawTrustedBundle(t *testing.T) {
	ctx := context.Background()

	t.Run("FetchLatestWithoutVerification", func(t *testing.T) {
		cfg := api.GetConfig{
			SkipVerify: true,
		}

		bundleData, err := api.GetRawTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("Failed to fetch bundle: %v", err)
		}

		if len(bundleData) == 0 {
			t.Fatal("Bundle data is empty")
		}

		// Check that it's a PEM file
		if !strings.Contains(string(bundleData), "BEGIN CERTIFICATE") {
			t.Error("Bundle doesn't contain PEM certificates")
		}

		// Check that it has metadata headers
		if !strings.Contains(string(bundleData), "## tpm-ca-certificates.pem") {
			t.Error("Bundle doesn't contain expected metadata header")
		}
	})

	t.Run("FetchSpecificDateWithoutVerification", func(t *testing.T) {
		cfg := api.GetConfig{
			Date:       "2025-12-05",
			SkipVerify: true,
		}

		bundleData, err := api.GetRawTrustedBundle(ctx, cfg)
		if err != nil {
			t.Fatalf("Failed to fetch bundle for specific date: %v", err)
		}

		if len(bundleData) == 0 {
			t.Fatal("Bundle data is empty")
		}

		// Check that the bundle has the correct date in metadata
		if !strings.Contains(string(bundleData), "## Date: 2025-12-05") {
			t.Error("Bundle doesn't contain expected date in metadata")
		}
	})

	t.Run("InvalidDate", func(t *testing.T) {
		cfg := api.GetConfig{
			Date:       "1999-01-01",
			SkipVerify: true,
		}

		_, err := api.GetRawTrustedBundle(ctx, cfg)
		if err == nil {
			t.Fatal("Expected error for non-existent release date")
		}

		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected 'not found' error, got: %v", err)
		}
	})
}

func TestVerifyTrustedBundle(t *testing.T) {
	ctx := context.Background()

	t.Run("VerifyWithAutoDetectedMetadataAndDownloadedChecksums", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping integration test in short mode")
		}

		// First download a bundle
		bundleData, err := api.GetRawTrustedBundle(ctx, api.GetConfig{
			Date:       "2025-12-05",
			SkipVerify: true,
		})
		if err != nil {
			t.Fatalf("Failed to download bundle: %v", err)
		}

		// Now verify it with auto-detected metadata and auto-downloaded checksums
		_, err = api.VerifyTrustedBundle(ctx, api.VerifyConfig{
			Bundle: bundleData,
		})
		if err != nil {
			t.Fatalf("Verification failed: %v", err)
		}
	})

	t.Run("EmptyBundleError", func(t *testing.T) {
		_, err := api.VerifyTrustedBundle(ctx, api.VerifyConfig{
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
		_, err := api.VerifyTrustedBundle(ctx, api.VerifyConfig{
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
		_, err := api.VerifyTrustedBundle(ctx, api.VerifyConfig{
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
