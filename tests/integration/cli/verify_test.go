package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
)

var testRepo = github.SourceRepo

const (
	// Test repository with known attestations
	testBundlePath    = "../testdata/tpm-ca-certificates.pem"
	testChecksumsPath = "../testdata/checksums.txt"
	testChecksumsSig  = "../testdata/checksums.txt.sigstore.json"
	testTag           = "2025-12-03"
	testCommit        = "7422b99b8b097ba8d80b4b7d3f27c13b78e35a7f"
	testWorkflow      = github.ReleaseBundleWorkflowPath

	// Expected digest for the test bundle
	// This is the actual digest of tpm-ca-certificates.pem from the 2025-12-03 release
	// (includes the metadata header with Date and Commit)
	expectedDigest = "sha256:604f64f1e807646b979f4c23f9a0be9da98d2f76132d54254cb79c4b4b4e4046"
)

// TestVerifyIntegration validates the complete verification workflow
// using the repository loicsikidi/tpm-ca-certificates.
//
// This test performs end-to-end verification including:
// 1. Computing the bundle digest
// 2. Creating the verifier
// 3. Verifying the bundle (Cosign + GitHub Attestations)
func TestVerifyIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Step 1: Read bundle and compute digest
	t.Log("Step 1: Reading bundle and computing digest...")
	bundleData, err := os.ReadFile(testBundlePath)
	if err != nil {
		t.Fatalf("Failed to read bundle: %v", err)
	}

	bundleDigest := digest.ComputeSHA256(bundleData)
	if bundleDigest != expectedDigest {
		t.Errorf("Unexpected digest: got %s, want %s", bundleDigest, expectedDigest)
	}
	t.Logf("✓ Digest: %s", bundleDigest)

	// Step 2: Create verifier
	t.Log("Step 2: Creating bundle verifier...")
	checksumData, err := os.ReadFile(testChecksumsPath)
	if err != nil {
		t.Fatalf("Failed to read checksums: %v", err)
	}
	checksumSigData, err := os.ReadFile(testChecksumsSig)
	if err != nil {
		t.Fatalf("Failed to read checksum signature: %v", err)
	}

	cfg := verifier.Config{
		Date:             testTag,
		Commit:           testCommit,
		SourceRepo:       &testRepo,
		WorkflowFilename: testWorkflow,
	}

	v, err := verifier.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}
	t.Log("✓ Verifier created")

	// Step 3: Verify bundle
	t.Log("Step 3: Verifying bundle...")
	result, err := v.Verify(context.Background(), bundleData, checksumData, checksumSigData, bundleDigest)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	// Validate results
	if result.CosignResult == nil {
		t.Error("Cosign result is nil")
	}
	if len(result.GithubAttestationResults) == 0 {
		t.Error("No attestation results")
	}

	t.Logf("✓ Verification succeeded")
	t.Logf("  - Cosign: verified")
	t.Logf("  - Attestations: %d verified", len(result.GithubAttestationResults))
}

// TestVerifyWithInvalidCommit verifies that verification fails when commit doesn't match.
func TestVerifyWithInvalidCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	bundleData, err := os.ReadFile(testBundlePath)
	if err != nil {
		t.Fatalf("Failed to read bundle: %v", err)
	}
	checksumData, err := os.ReadFile(testChecksumsPath)
	if err != nil {
		t.Fatalf("Failed to read checksums: %v", err)
	}
	checksumSigData, err := os.ReadFile(testChecksumsSig)
	if err != nil {
		t.Fatalf("Failed to read checksum signature: %v", err)
	}

	bundleDigest := digest.ComputeSHA256(bundleData)

	// Use a wrong commit
	wrongCommit := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	cfg := verifier.Config{
		Date:             testTag,
		Commit:           wrongCommit, // Wrong commit
		SourceRepo:       &testRepo,
		WorkflowFilename: testWorkflow,
	}

	v, err := verifier.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Verification should fail due to commit mismatch
	_, err = v.Verify(context.Background(), bundleData, checksumData, checksumSigData, bundleDigest)
	if err == nil {
		t.Error("Expected verification to fail with wrong commit, but it succeeded")
	} else {
		t.Logf("✓ Verification correctly failed with wrong commit: %v", err)
	}
}

// TestVerifyWithInvalidDate verifies that verification fails when date doesn't match.
func TestVerifyWithInvalidDate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	bundleData, err := os.ReadFile(testBundlePath)
	if err != nil {
		t.Fatalf("Failed to read bundle: %v", err)
	}
	checksumData, err := os.ReadFile(testChecksumsPath)
	if err != nil {
		t.Fatalf("Failed to read checksums: %v", err)
	}
	checksumSigData, err := os.ReadFile(testChecksumsSig)
	if err != nil {
		t.Fatalf("Failed to read checksum signature: %v", err)
	}

	bundleDigest := digest.ComputeSHA256(bundleData)

	// Use a wrong date
	wrongDate := "2024-01-01"

	cfg := verifier.Config{
		Date:             wrongDate, // Wrong date
		Commit:           testCommit,
		SourceRepo:       &testRepo,
		WorkflowFilename: testWorkflow,
	}

	v, err := verifier.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Verification should fail due to date mismatch
	_, err = v.Verify(context.Background(), bundleData, checksumData, checksumSigData, bundleDigest)
	if err == nil {
		t.Error("Expected verification to fail with wrong date, but it succeeded")
	} else {
		t.Logf("✓ Verification correctly failed with wrong date: %v", err)
	}
}

// TestDigestComputation validates the digest computation separately.
func TestDigestComputation(t *testing.T) {
	bundleData, err := os.ReadFile(testBundlePath)
	if err != nil {
		t.Fatalf("Failed to read bundle: %v", err)
	}

	bundleDigest := digest.ComputeSHA256(bundleData)
	if bundleDigest != expectedDigest {
		t.Errorf("Digest mismatch:\ngot:  %s\nwant: %s", bundleDigest, expectedDigest)
	}
}

// TestBundleLocation tests that the bundle can be found in different locations.
func TestBundleLocation(t *testing.T) {
	// Test with file in current directory
	t.Run("current_directory", func(t *testing.T) {
		tmpFile, err := os.CreateTemp(".", "test-bundle-*.pem")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.WriteString("test content")
		tmpFile.Close()

		data, err := os.ReadFile(tmpFile.Name())
		if err != nil {
			t.Errorf("Failed to read file in current dir: %v", err)
		}
		_ = digest.ComputeSHA256(data)
	})

	// Test with file in subdirectory
	t.Run("subdirectory", func(t *testing.T) {
		tmpDir := t.TempDir()
		bundlePath := filepath.Join(tmpDir, "bundle.pem")

		testData := []byte("test content")
		if err := os.WriteFile(bundlePath, testData, 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		_ = digest.ComputeSHA256(testData)
	})
}
