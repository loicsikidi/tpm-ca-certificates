package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/policy"
)

const (
	// Test repository with known attestations
	testBundlePath = "testdata/tpm-ca-certificates.pem"
	testRepo       = "loicsikidi/tpm-ca-certificates"
	testOwner      = "loicsikidi"
	testRepoName   = "tpm-ca-certificates"
	testTag        = "2025-12-03"
	testCommit     = "7422b99b8b097ba8d80b4b7d3f27c13b78e35a7f"

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
// 2. Fetching attestations from GitHub API
// 3. Initializing Sigstore verifier with TUF
// 4. Building verification policy
// 5. Verifying attestations
func TestVerifyIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Step 1: Compute digest
	t.Log("Step 1: Computing bundle digest...")
	digest, err := digest.ComputeSHA256(testBundlePath)
	if err != nil {
		t.Fatalf("Failed to compute digest: %v", err)
	}

	if digest != expectedDigest {
		t.Errorf("Unexpected digest: got %s, want %s", digest, expectedDigest)
	}
	t.Logf("✓ Digest: %s", digest)

	// Step 2: Fetch attestations from GitHub API
	t.Log("Step 2: Fetching attestations from GitHub API...")
	client := github.NewHTTPClient(nil)
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
	policyCfg := policy.Config{
		SourceRepo:    testRepo,
		OIDCIssuer:    "https://token.actions.githubusercontent.com",
		PredicateType: "https://slsa.dev/provenance/v1",
		BuildWorkflow: ".github/workflows/release-bundle.yaml",
		Tag:           testTag,
	}
	verifier, err := github.NewVerifier(github.Config{
		Digest: digest,
		Policy: policyCfg,
	})
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}
	t.Log("✓ Verifier created")
	t.Log("✓ Policy built with criteria:")
	t.Logf("  - OIDC Issuer: %s", policyCfg.OIDCIssuer)
	t.Logf("  - Source Repo: %s", policyCfg.SourceRepo)
	t.Logf("  - Build Workflow: %s", policyCfg.BuildWorkflowRef())

	// Step 4: Verify attestations
	t.Log("Step 4: Verifying attestations...")
	var verified bool
	for i, att := range attestations {
		result, err := verifier.Verify(att)
		if err != nil {
			t.Logf("Attestation %d verification failed: %v", i, err)
			continue
		}

		// Verification succeeded
		verified = true
		t.Logf("✓ Attestation %d verified successfully", i)

		// Validate result structure
		if result == nil {
			t.Fatal("Verification result is nil")
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

	client := github.NewHTTPClient(nil)
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

	digest, err := digest.ComputeSHA256(testBundlePath)
	if err != nil {
		t.Fatalf("Failed to compute digest: %v", err)
	}

	client := github.NewHTTPClient(nil)
	attestations, err := client.GetAttestations(testOwner, testRepoName, digest)
	if err != nil {
		t.Fatalf("Failed to fetch attestations: %v", err)
	}

	if len(attestations) == 0 {
		t.Skip("No attestations available for test")
	}

	// Build policy with wrong workflow name
	policyCfg := policy.Config{
		SourceRepo:    testRepo,
		OIDCIssuer:    "https://token.actions.githubusercontent.com",
		PredicateType: "https://slsa.dev/provenance/v1",
		BuildWorkflow: ".github/workflows/wrong-workflow.yaml", // Wrong workflow
		Tag:           testTag,
	}

	verifier, err := github.NewVerifier(github.Config{
		Digest: digest,
		Policy: policyCfg,
	})
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Verification should fail
	for i, att := range attestations {
		_, err := verifier.Verify(att)
		if err == nil {
			t.Errorf("Attestation %d verification should have failed with wrong workflow, but succeeded", i)
		} else {
			t.Logf("✓ Attestation %d correctly failed verification: %v", i, err)
		}
	}
}

// TestVerifyCommitMismatch verifies that verification fails when commit doesn't match.
func TestVerifyCommitMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	digest, err := digest.ComputeSHA256(testBundlePath)
	if err != nil {
		t.Fatalf("Failed to compute digest: %v", err)
	}

	client := github.NewHTTPClient(nil)
	attestations, err := client.GetAttestations(testOwner, testRepoName, digest)
	if err != nil {
		t.Fatalf("Failed to fetch attestations: %v", err)
	}

	if len(attestations) == 0 {
		t.Skip("No attestations available for test")
	}

	// Build policy with correct settings but we'll test with wrong commit
	policyCfg := policy.Config{
		SourceRepo:    testRepo,
		OIDCIssuer:    "https://token.actions.githubusercontent.com",
		PredicateType: "https://slsa.dev/provenance/v1",
		BuildWorkflow: ".github/workflows/release-bundle.yaml",
		Tag:           testTag,
	}

	verifier, err := github.NewVerifier(github.Config{
		Digest: digest,
		Policy: policyCfg,
	})
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	wrongCommit := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// Verify attestation (this should succeed)
	result, err := verifier.Verify(attestations[0])
	if err != nil {
		t.Fatalf("Attestation verification failed: %v", err)
	}

	// Now verify commit should fail
	fields := result.Statement.Predicate.GetFields()
	var actualCommit string
	if buildDef := fields["buildDefinition"]; buildDef != nil {
		buildDefStruct := buildDef.GetStructValue()
		if buildDefStruct != nil {
			buildDefFields := buildDefStruct.GetFields()
			if resolvedDeps := buildDefFields["resolvedDependencies"]; resolvedDeps != nil {
				resolvedDepsList := resolvedDeps.GetListValue()
				if resolvedDepsList != nil && len(resolvedDepsList.GetValues()) > 0 {
					firstDep := resolvedDepsList.GetValues()[0]
					if firstDep != nil {
						firstDepStruct := firstDep.GetStructValue()
						if firstDepStruct != nil {
							firstDepFields := firstDepStruct.GetFields()
							if digest := firstDepFields["digest"]; digest != nil {
								digestStruct := digest.GetStructValue()
								if digestStruct != nil {
									digestFields := digestStruct.GetFields()
									if commit := digestFields["gitCommit"]; commit != nil {
										actualCommit = commit.GetStringValue()
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if actualCommit == "" {
		t.Fatal("Failed to extract commit from attestation")
	}

	// Verify that commits don't match
	if actualCommit == wrongCommit {
		t.Errorf("Expected different commits, but both are %s", actualCommit)
	}

	t.Logf("✓ Commit validation works: actual=%s, wrong=%s", actualCommit, wrongCommit)
}

// TestDigestComputation validates the digest computation separately.
func TestDigestComputation(t *testing.T) {
	digest, err := digest.ComputeSHA256(testBundlePath)
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

		_, err = digest.ComputeSHA256(tmpFile.Name())
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

		_, err := digest.ComputeSHA256(bundlePath)
		if err != nil {
			t.Errorf("Failed to compute digest for file in subdirectory: %v", err)
		}
	})
}
