package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/attestation"
)

const (
	// Test repository with known attestations
	testRepo     = "loicsikidi/test-hybrid-release"
	testOwner    = "loicsikidi"
	testRepoName = "test-hybrid-release"
	testTag      = "2025-01-03"
	testCommit   = "a703c9c414fcad56351b5b6326a7d0cbaf2f0b9c"

	// Expected digest for the test bundle
	// This is the actual digest of tpm-ca-certificates.pem from the test release
	expectedDigest = "sha256:ac58579d398a60f0d610b0bd405c983ff30a91a551ca57dd4ca30aee2536cc4a"
)

// TestVerifyIntegration validates the complete verification workflow
// using the test repository loicsikidi/test-hybrid-release.
//
// This test performs end-to-end verification including:
// 1. Computing the bundle digest
// 2. Fetching attestations from GitHub API
// 3. Initializing Sigstore verifier with TUF
// 4. Building verification policy
// 5. Verifying attestations
func TestVerifyIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create temporary test bundle
	bundlePath := createTestBundle(t)
	defer os.Remove(bundlePath)

	// Step 1: Compute digest
	t.Log("Step 1: Computing bundle digest...")
	digest, err := attestation.ComputeSHA256(bundlePath)
	if err != nil {
		t.Fatalf("Failed to compute digest: %v", err)
	}

	if digest != expectedDigest {
		t.Errorf("Unexpected digest: got %s, want %s", digest, expectedDigest)
	}
	t.Logf("✓ Digest: %s", digest)

	// Step 2: Fetch attestations from GitHub API
	t.Log("Step 2: Fetching attestations from GitHub API...")
	client := attestation.NewHTTPClient(nil)
	attestations, err := client.GetAttestations(testOwner, testRepoName, digest)
	if err != nil {
		t.Fatalf("Failed to fetch attestations: %v", err)
	}

	if len(attestations) == 0 {
		t.Fatal("No attestations found")
	}
	t.Logf("✓ Loaded %d attestation(s)", len(attestations))

	// Verify that bundles are properly loaded
	for i, att := range attestations {
		if att.Bundle == nil {
			t.Errorf("Attestation %d has nil bundle", i)
		}
	}

	// Step 3: Create verifier
	t.Log("Step 3: Creating Sigstore verifier...")
	verifier, err := attestation.NewVerifier()
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}
	t.Log("✓ Verifier created")

	// Step 4: Build policy
	t.Log("Step 4: Building verification policy...")
	policyOpts := attestation.PolicyOptions{
		SourceRepo:    testRepo,
		OIDCIssuer:    "https://token.actions.githubusercontent.com",
		PredicateType: "https://slsa.dev/provenance/v1",
		BuildWorkflow: ".github/workflows/release-bundle.yml",
		Tag:           testTag,
	}

	policy, err := attestation.BuildPolicy(digest, policyOpts)
	if err != nil {
		t.Fatalf("Failed to build policy: %v", err)
	}
	t.Log("✓ Policy built with criteria:")
	t.Logf("  - OIDC Issuer: %s", policyOpts.OIDCIssuer)
	t.Logf("  - Source Repo: %s", policyOpts.SourceRepo)
	t.Logf("  - Build Workflow: %s@refs/tags/%s", policyOpts.BuildWorkflow, policyOpts.Tag)

	// Step 5: Verify attestations
	t.Log("Step 5: Verifying attestations...")
	var verified bool
	for i, att := range attestations {
		result, err := verifier.Verify(att, policy)
		if err != nil {
			t.Logf("Attestation %d verification failed: %v", i, err)
			continue
		}

		// Verification succeeded
		verified = true
		t.Logf("✓ Attestation %d verified successfully", i)

		// Validate result structure
		if result == nil {
			t.Error("Verification result is nil")
		}
		if result.Signature == nil {
			t.Error("Signature in result is nil")
		}

		break // One successful verification is enough
	}

	if !verified {
		t.Fatal("No attestations passed verification")
	}

	t.Log("✓ Verification succeeded")
}

// TestVerifyInvalidDigest verifies that verification fails with an invalid digest.
func TestVerifyInvalidDigest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	invalidDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	client := attestation.NewHTTPClient(nil)
	attestations, err := client.GetAttestations(testOwner, testRepoName, invalidDigest)

	// Either no attestations found or error - both are acceptable
	if err == nil && len(attestations) > 0 {
		t.Error("Expected no attestations for invalid digest, but got some")
	}
}

// TestVerifyPolicyMismatch verifies that verification fails with incorrect policy.
func TestVerifyPolicyMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	bundlePath := createTestBundle(t)
	defer os.Remove(bundlePath)

	digest, err := attestation.ComputeSHA256(bundlePath)
	if err != nil {
		t.Fatalf("Failed to compute digest: %v", err)
	}

	client := attestation.NewHTTPClient(nil)
	attestations, err := client.GetAttestations(testOwner, testRepoName, digest)
	if err != nil {
		t.Fatalf("Failed to fetch attestations: %v", err)
	}

	if len(attestations) == 0 {
		t.Skip("No attestations available for test")
	}

	verifier, err := attestation.NewVerifier()
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Build policy with wrong workflow name
	policyOpts := attestation.PolicyOptions{
		SourceRepo:    testRepo,
		OIDCIssuer:    "https://token.actions.githubusercontent.com",
		PredicateType: "https://slsa.dev/provenance/v1",
		BuildWorkflow: ".github/workflows/wrong-workflow.yml", // Wrong workflow
		Tag:           testTag,
	}

	policy, err := attestation.BuildPolicy(digest, policyOpts)
	if err != nil {
		t.Fatalf("Failed to build policy: %v", err)
	}

	// Verification should fail
	for i, att := range attestations {
		_, err := verifier.Verify(att, policy)
		if err == nil {
			t.Errorf("Attestation %d verification should have failed with wrong workflow, but succeeded", i)
		} else {
			t.Logf("✓ Attestation %d correctly failed verification: %v", i, err)
		}
	}
}

// createTestBundle creates a temporary file with the test certificate content.
//
// This is the actual content from the test-hybrid-release repository.
func createTestBundle(t *testing.T) string {
	t.Helper()

	// This is the actual content of tpm-ca-certificates.pem from test-hybrid-release
	bundleContent := `-----BEGIN CERTIFICATE-----
MIIBdjCCARygAwIBAgIRAKjIOzWTCC66SJLRB5eewJMwCgYIKoZIzj0EAwIwGTEX
MBUGA1UEAxMOTWluaUNBIFJvb3QgQ0EwHhcNMjUxMTI5MTY0NzEyWhcNMjUxMTMw
MTY0NzEyWjAZMRcwFQYDVQQDEw5NaW5pQ0EgUm9vdCBDQTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABJ5ZcPVrm5WIroTQM0PcVCxnTiwIzJDvQSnAoJO7nny2ezTv
Ln6ysc9EUMyRJA1hjwLqb2yaNCbdMQ5xh52A8MOjRTBDMA4GA1UdDwEB/wQEAwIB
BjASBgNVHRMBAf8ECDAGAQH/AgEBMB0GA1UdDgQWBBSAykAbjjr1GLB2d/qrvv5x
hWsmNjAKBggqhkjOPQQDAgNIADBFAiA0PhgsJ+CFea3nKLJm09tt+RQIZavbV+Cw
gVfsRDq+JQIhAIVaPP1n1jNPKP+fjOIXHQCzaCK7WSQe8KuQwpzZszVE
-----END CERTIFICATE-----
`

	tmpFile, err := os.CreateTemp("", "tpm-ca-certificates-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	if _, err := tmpFile.WriteString(bundleContent); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to write bundle content: %v", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		t.Fatalf("Failed to close temp file: %v", err)
	}

	return tmpFile.Name()
}

// TestDigestComputation validates the digest computation separately.
func TestDigestComputation(t *testing.T) {
	bundlePath := createTestBundle(t)
	defer os.Remove(bundlePath)

	digest, err := attestation.ComputeSHA256(bundlePath)
	if err != nil {
		t.Fatalf("Failed to compute digest: %v", err)
	}

	if digest != expectedDigest {
		t.Errorf("Digest mismatch:\ngot:  %s\nwant: %s", digest, expectedDigest)
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

		_, err = attestation.ComputeSHA256(tmpFile.Name())
		if err != nil {
			t.Errorf("Failed to compute digest for file in current dir: %v", err)
		}
	})

	// Test with file in subdirectory
	t.Run("subdirectory", func(t *testing.T) {
		tmpDir := t.TempDir()
		bundlePath := filepath.Join(tmpDir, "bundle.pem")

		if err := os.WriteFile(bundlePath, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		_, err := attestation.ComputeSHA256(bundlePath)
		if err != nil {
			t.Errorf("Failed to compute digest for file in subdirectory: %v", err)
		}
	})
}
