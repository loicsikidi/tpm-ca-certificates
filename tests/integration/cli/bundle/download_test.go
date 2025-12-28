package bundle_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/cmd/bundle/download"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
)

func TestDownloadCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that downloads from GitHub")
	}

	tests := []struct {
		name             string
		date             string
		expectedChecksum string
	}{
		{
			name:             "download bundle for 2025-12-10",
			date:             "2025-12-10",
			expectedChecksum: "90ac2af61924b0db6ff40da7b8ff5b722652381410bc642b4a558eb8053e7809",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			os.Stdout = w

			// Create download config
			opts := &download.Opts{
				Date:       tt.date,
				OutputDir:  "-",
				Type:       "root",
				SkipVerify: false,
				Force:      false,
				CacheDir:   t.TempDir(),
			}

			// Run download in a goroutine
			errCh := make(chan error, 1)
			go func() {
				errCh <- download.Run(t.Context(), opts)
			}()

			// Read output
			var stdout bytes.Buffer
			done := make(chan bool)
			go func() {
				_, _ = io.Copy(&stdout, r)
				done <- true
			}()

			// Wait for command to finish
			if err := <-errCh; err != nil {
				w.Close()
				<-done
				os.Stdout = oldStdout
				t.Fatalf("download command failed: %v", err)
			}

			// Close pipe and restore stdout
			w.Close()
			<-done
			os.Stdout = oldStdout

			// Compute SHA256 checksum
			bundleData := stdout.Bytes()
			if len(bundleData) == 0 {
				t.Fatal("downloaded bundle is empty")
			}

			hash := sha256.Sum256(bundleData)
			actualChecksum := hex.EncodeToString(hash[:])

			// Verify checksum
			if actualChecksum != tt.expectedChecksum {
				t.Errorf("checksum mismatch:\nexpected: %s\ngot:      %s", tt.expectedChecksum, actualChecksum)
			}

			t.Logf("✓ Successfully downloaded and verified bundle for %s", tt.date)
			t.Logf("✓ SHA256: %s", actualChecksum)
		})
	}
}

func TestDownloadCommand_BothBundles_2025_12_27(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that downloads from GitHub")
	}

	// Create a temporary directory for output
	tmpDir := t.TempDir()

	opts := &download.Opts{
		Date:       "2025-12-27",
		OutputDir:  tmpDir,
		Type:       "", // Download both bundles
		SkipVerify: false,
		Force:      false,
		CacheDir:   t.TempDir(),
	}

	if err := download.Run(t.Context(), opts); err != nil {
		t.Fatalf("download command failed: %v", err)
	}

	// Verify root bundle exists
	rootBundlePath := filepath.Join(tmpDir, apiv1beta.CacheRootBundleFilename)
	if !utils.FileExists(rootBundlePath) {
		t.Fatalf("root bundle not found at %s", rootBundlePath)
	}

	// Verify intermediate bundle exists (2025-12-27 has intermediate bundle)
	intermediateBundlePath := filepath.Join(tmpDir, apiv1beta.CacheIntermediateBundleFilename)
	if !utils.FileExists(intermediateBundlePath) {
		t.Fatalf("intermediate bundle not found at %s", intermediateBundlePath)
	}

	// Read and verify root bundle is not empty
	rootData, err := utils.ReadFile(rootBundlePath)
	if err != nil {
		t.Fatalf("failed to read root bundle: %v", err)
	}
	if len(rootData) == 0 {
		t.Fatal("root bundle is empty")
	}

	// Read and verify intermediate bundle is not empty
	intermediateData, err := utils.ReadFile(intermediateBundlePath)
	if err != nil {
		t.Fatalf("failed to read intermediate bundle: %v", err)
	}
	if len(intermediateData) == 0 {
		t.Fatal("intermediate bundle is empty")
	}

	t.Logf("✓ Successfully downloaded both bundles for 2025-12-27")
	t.Logf("✓ Root bundle size: %d bytes", len(rootData))
	t.Logf("✓ Intermediate bundle size: %d bytes", len(intermediateData))
}

func TestDownloadCommand_RootOnly_2025_12_05(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that downloads from GitHub")
	}

	// Create a temporary directory for output
	tmpDir := t.TempDir()

	opts := &download.Opts{
		Date:       testutil.BundleVersion,
		OutputDir:  tmpDir,
		Type:       "", // Download both bundles (but only root available)
		SkipVerify: false,
		Force:      false,
		CacheDir:   t.TempDir(),
	}

	if err := download.Run(t.Context(), opts); err != nil {
		t.Fatalf("download command failed: %v", err)
	}

	// Verify root bundle exists
	rootBundlePath := filepath.Join(tmpDir, apiv1beta.CacheRootBundleFilename)
	if !utils.FileExists(rootBundlePath) {
		t.Fatalf("root bundle not found at %s", rootBundlePath)
	}

	// Verify intermediate bundle does NOT exist (2025-12-05 doesn't have intermediate bundle)
	intermediateBundlePath := filepath.Join(tmpDir, apiv1beta.CacheIntermediateBundleFilename)
	if utils.FileExists(intermediateBundlePath) {
		t.Fatalf("intermediate bundle should not exist for 2025-12-05, but found at %s", intermediateBundlePath)
	}

	// Read and verify root bundle is not empty
	rootData, err := utils.ReadFile(rootBundlePath)
	if err != nil {
		t.Fatalf("failed to read root bundle: %v", err)
	}
	if len(rootData) == 0 {
		t.Fatal("root bundle is empty")
	}

	t.Logf("✓ Successfully downloaded root bundle for 2025-12-05")
	t.Logf("✓ Root bundle size: %d bytes", len(rootData))
	t.Logf("✓ Intermediate bundle correctly not downloaded (not available)")
}

func TestDownloadCommand_IntermediateNotAvailable_2025_12_05(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that downloads from GitHub")
	}

	// Create a temporary directory for output
	tmpDir := t.TempDir()

	opts := &download.Opts{
		Date:       testutil.BundleVersion,
		OutputDir:  tmpDir,
		Type:       "intermediate", // Explicitly request intermediate
		SkipVerify: false,
		Force:      false,
		CacheDir:   t.TempDir(),
	}

	err := download.Run(t.Context(), opts)
	if err == nil {
		t.Fatal("expected error when requesting intermediate bundle for 2025-12-05, but got none")
	}

	expectedErrMsg := "intermediate bundle not available for this release"
	if err.Error() != expectedErrMsg {
		t.Errorf("expected error message %q, got %q", expectedErrMsg, err.Error())
	}

	t.Logf("✓ Correctly returned error when requesting unavailable intermediate bundle")
}

func TestDownloadCommand_TypeRoot_2025_12_27(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that downloads from GitHub")
	}

	// Create a temporary directory for output
	tmpDir := t.TempDir()

	opts := &download.Opts{
		Date:       "2025-12-27",
		OutputDir:  tmpDir,
		Type:       "root", // Only root bundle
		SkipVerify: false,
		Force:      false,
		CacheDir:   t.TempDir(),
	}

	if err := download.Run(t.Context(), opts); err != nil {
		t.Fatalf("download command failed: %v", err)
	}

	// Verify root bundle exists
	rootBundlePath := filepath.Join(tmpDir, apiv1beta.CacheRootBundleFilename)
	if !utils.FileExists(rootBundlePath) {
		t.Fatalf("root bundle not found at %s", rootBundlePath)
	}

	// Verify intermediate bundle does NOT exist (explicitly requested only root)
	intermediateBundlePath := filepath.Join(tmpDir, apiv1beta.CacheIntermediateBundleFilename)
	if utils.FileExists(intermediateBundlePath) {
		t.Fatalf("intermediate bundle should not exist when --type root, but found at %s", intermediateBundlePath)
	}

	t.Logf("✓ Successfully downloaded only root bundle when --type root")
}

func TestDownloadCommand_TypeIntermediate_2025_12_27(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that downloads from GitHub")
	}

	// Create a temporary directory for output
	tmpDir := t.TempDir()

	opts := &download.Opts{
		Date:       "2025-12-27",
		OutputDir:  tmpDir,
		Type:       "intermediate", // Only intermediate bundle
		SkipVerify: false,
		Force:      false,
		CacheDir:   t.TempDir(),
	}

	if err := download.Run(t.Context(), opts); err != nil {
		t.Fatalf("download command failed: %v", err)
	}

	// Verify intermediate bundle exists
	intermediateBundlePath := filepath.Join(tmpDir, apiv1beta.CacheIntermediateBundleFilename)
	if !utils.FileExists(intermediateBundlePath) {
		t.Fatalf("intermediate bundle not found at %s", intermediateBundlePath)
	}

	// Verify root bundle does NOT exist (explicitly requested only intermediate)
	rootBundlePath := filepath.Join(tmpDir, apiv1beta.CacheRootBundleFilename)
	if utils.FileExists(rootBundlePath) {
		t.Fatalf("root bundle should not exist when --type intermediate, but found at %s", rootBundlePath)
	}

	t.Logf("✓ Successfully downloaded only intermediate bundle when --type intermediate")
}

func TestDownloadCommand_StdoutWithoutType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that downloads from GitHub")
	}

	opts := &download.Opts{
		Date:       "2025-12-27",
		OutputDir:  "-",
		Type:       "", // No type specified
		SkipVerify: false,
		Force:      false,
		CacheDir:   t.TempDir(),
	}

	err := download.Run(t.Context(), opts)
	if err == nil {
		t.Fatal("expected error when using stdout without --type, but got none")
	}

	expectedErrMsg := "when using stdout (--output-dir -), you must specify --type (root or intermediate)"
	if err.Error() != expectedErrMsg {
		t.Errorf("expected error message %q, got %q", expectedErrMsg, err.Error())
	}

	t.Logf("✓ Correctly returned error when using stdout without --type")
}
