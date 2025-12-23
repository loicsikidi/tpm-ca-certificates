package integration

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

var (
	testRepo = github.SourceRepo
	testTag  = testutil.BundleVersion
)

const (
	testCommit   = "1e869770ff7c125a45735f30a959df2bb3e7b465"
	testWorkflow = github.ReleaseBundleWorkflowPath

	// Expected digest for the test bundle
	// This is the actual digest of tpm-ca-certificates.pem from the 2025-12-03 release
	// (includes the metadata header with Date and Commit)
	expectedDigest = "sha256:f5c7f9e9c59d65f1a889b1cdc712a3ea674df84bd8dc15081165b41ac2496ed2"
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
	bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
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
	checksumData, err := testutil.ReadTestFile(testutil.ChecksumFile)
	if err != nil {
		t.Fatalf("Failed to read checksums: %v", err)
	}
	checksumSigData, err := testutil.ReadTestFile(testutil.ChecksumSigstoreFile)
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

	provenanceData, err := testutil.ReadTestFile(testutil.ProvenanceFile)
	if err != nil {
		t.Fatalf("Failed to read provenance: %v", err)
	}

	// Step 3: Verify bundle
	t.Log("Step 3: Verifying bundle...")
	result, err := v.Verify(context.Background(), bundleData, checksumData, checksumSigData, provenanceData, bundleDigest)
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

	bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
	if err != nil {
		t.Fatalf("Failed to read bundle: %v", err)
	}
	checksumData, err := testutil.ReadTestFile(testutil.ChecksumFile)
	if err != nil {
		t.Fatalf("Failed to read checksums: %v", err)
	}
	checksumSigData, err := testutil.ReadTestFile(testutil.ChecksumSigstoreFile)
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

	provenanceData, err := testutil.ReadTestFile(testutil.ProvenanceFile)
	if err != nil {
		t.Fatalf("Failed to read provenance: %v", err)
	}

	// Verification should fail due to commit mismatch
	_, err = v.Verify(context.Background(), bundleData, checksumData, checksumSigData, provenanceData, bundleDigest)
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

	bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
	if err != nil {
		t.Fatalf("Failed to read bundle: %v", err)
	}
	checksumData, err := testutil.ReadTestFile(testutil.ChecksumFile)
	if err != nil {
		t.Fatalf("Failed to read checksums: %v", err)
	}
	checksumSigData, err := testutil.ReadTestFile(testutil.ChecksumSigstoreFile)
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

	provenanceData, err := testutil.ReadTestFile(testutil.ProvenanceFile)
	if err != nil {
		t.Fatalf("Failed to read provenance: %v", err)
	}

	// Verification should fail due to date mismatch
	_, err = v.Verify(context.Background(), bundleData, checksumData, checksumSigData, provenanceData, bundleDigest)
	if err == nil {
		t.Error("Expected verification to fail with wrong date, but it succeeded")
	} else {
		t.Logf("✓ Verification correctly failed with wrong date: %v", err)
	}
}

// TestDigestComputation validates the digest computation separately.
func TestDigestComputation(t *testing.T) {
	bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
	if err != nil {
		t.Fatalf("Failed to read bundle: %v", err)
	}

	bundleDigest := digest.ComputeSHA256(bundleData)
	if bundleDigest != expectedDigest {
		t.Errorf("Digest mismatch:\ngot:  %s\nwant: %s", bundleDigest, expectedDigest)
	}
}

// TestReadFileFromStdin validates that ReadFile can read from stdin.
func TestReadFileFromStdin(t *testing.T) {
	bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
	if err != nil {
		t.Fatalf("Failed to read bundle: %v", err)
	}

	// Save original stdin
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	// Create a pipe and simulate stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	os.Stdin = r

	// Write bundle data to pipe in a goroutine
	go func() {
		defer w.Close()
		w.Write(bundleData)
	}()

	// Read from stdin using ReadFile("-")
	stdinData, err := utils.ReadFile("-")
	if err != nil {
		t.Fatalf("ReadFile(\"-\") failed: %v", err)
	}

	// Verify the data matches
	if !bytes.Equal(stdinData, bundleData) {
		t.Errorf("Data mismatch:\ngot length:  %d\nwant length: %d", len(stdinData), len(bundleData))
	}

	// Verify the digest matches
	stdinDigest := digest.ComputeSHA256(stdinData)
	bundleDigest := digest.ComputeSHA256(bundleData)
	if stdinDigest != bundleDigest {
		t.Errorf("Digest mismatch:\ngot:  %s\nwant: %s", stdinDigest, bundleDigest)
	}

	t.Logf("✓ Successfully read %d bytes from stdin", len(stdinData))
	t.Logf("✓ Digest: %s", stdinDigest)
}
