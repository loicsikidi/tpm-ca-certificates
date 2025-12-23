package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/cosign"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/policy"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/verifier"
)

// contains checks if a string contains a substring.
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// testPolicyConfig returns a valid policy.Config for testing purposes.
func testPolicyConfig(metadata *bundle.Metadata) policy.Config {
	return policy.Config{
		SourceRepo:    &github.SourceRepo,
		OIDCIssuer:    "https://token.actions.githubusercontent.com",
		BuildWorkflow: github.ReleaseBundleWorkflowPath,
		Tag:           metadata.Date,
	}
}

func TestCosignVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	checksumData, err := testutil.ReadTestFile(testutil.ChecksumFile)
	if err != nil {
		t.Fatalf("Failed to read checksum file: %v", err)
	}
	signatureData, err := testutil.ReadTestFile(testutil.ChecksumSigstoreFile)
	if err != nil {
		t.Fatalf("Failed to read signature file: %v", err)
	}
	bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
	if err != nil {
		t.Fatalf("Failed to read bundle file: %v", err)
	}

	metadata, err := bundle.ParseMetadata(bundleData)
	if err != nil {
		t.Fatalf("Failed to parse bundle metadata: %v", err)
	}

	ctx := context.Background()
	cfg := testPolicyConfig(metadata)
	verifierCfg := verifier.Config{}

	t.Run("VerifyValidSignature", func(t *testing.T) {
		result, err := cosign.VerifyChecksum(ctx, cfg, verifierCfg, checksumData, signatureData, bundleData, testutil.BundleFile)
		if err != nil {
			t.Fatalf("Expected successful verification, got error: %v", err)
		}
		if result == nil {
			t.Fatal("Expected non-nil verification result")
		}
	})

	t.Run("VerifyInvalidChecksum", func(t *testing.T) {
		// Create invalid bundle data
		invalidData := []byte("invalid content\n")

		// Verification should fail because checksum doesn't match
		_, err = cosign.VerifyChecksum(ctx, cfg, verifierCfg, checksumData, signatureData, invalidData, testutil.BundleFile)
		if err == nil {
			t.Fatal("Expected verification to fail with invalid checksum, but it succeeded")
		}
		if !contains(err.Error(), "checksum mismatch") {
			t.Errorf("Expected error about checksum mismatch, got: %v", err)
		}
	})

	t.Run("VerifyInvalidSignatureData", func(t *testing.T) {
		// Use invalid signature data
		invalidSignature := []byte("invalid json")

		_, err = cosign.VerifyChecksum(ctx, cfg, verifierCfg, checksumData, invalidSignature, bundleData, testutil.BundleFile)
		if err == nil {
			t.Fatal("Expected verification to fail with invalid signature data, but it succeeded")
		}
		if !contains(err.Error(), "failed to load signature bundle") {
			t.Errorf("Expected error about loading signature bundle, got: %v", err)
		}
	})
}

func TestFindChecksumFiles(t *testing.T) {
	t.Run("AutoDetectSuccess", func(t *testing.T) {
		// Write test files to temp dir
		tmpDir := t.TempDir()
		bundlePath := filepath.Join(tmpDir, "tpm-ca-certificates.pem")
		checksumPath := filepath.Join(tmpDir, "checksums.txt")
		signaturePath := filepath.Join(tmpDir, "checksums.txt.sigstore.json")

		bundleData, _ := testutil.ReadTestFile(testutil.BundleFile)
		checksumData, _ := testutil.ReadTestFile(testutil.ChecksumFile)
		signatureData, _ := testutil.ReadTestFile(testutil.ChecksumSigstoreFile)

		os.WriteFile(bundlePath, bundleData, 0644)
		os.WriteFile(checksumPath, checksumData, 0644)
		os.WriteFile(signaturePath, signatureData, 0644)

		foundChecksumPath, foundSignaturePath, found := cosign.FindChecksumFiles(tmpDir)
		if !found {
			t.Fatal("Expected to find checksum files, but none were found")
		}

		if foundChecksumPath != checksumPath {
			t.Errorf("Expected checksums path %s, got %s", checksumPath, foundChecksumPath)
		}
		if foundSignaturePath != signaturePath {
			t.Errorf("Expected signature path %s, got %s", signaturePath, foundSignaturePath)
		}
	})

	t.Run("AutoDetectFailure", func(t *testing.T) {
		tmpDir := t.TempDir()
		tmpBundle := filepath.Join(tmpDir, "bundle.pem")
		if err := os.WriteFile(tmpBundle, []byte("test"), 0644); err != nil {
			t.Fatalf("Failed to create temp bundle: %v", err)
		}

		checksumPath, signaturePath, found := cosign.FindChecksumFiles(tmpBundle)
		if found {
			t.Fatal("Expected not to find checksum files, but they were found")
		}
		if checksumPath != "" || signaturePath != "" {
			t.Errorf("Expected empty paths when files not found, got checksums=%s, signature=%s",
				checksumPath, signaturePath)
		}
	})
}

func TestValidateChecksumFilesExist(t *testing.T) {
	tmpDir := t.TempDir()
	checksumPath := filepath.Join(tmpDir, "checksums.txt")
	signaturePath := filepath.Join(tmpDir, "checksums.txt.sigstore.json")

	checksumData, _ := testutil.ReadTestFile(testutil.ChecksumFile)
	signatureData, _ := testutil.ReadTestFile(testutil.ChecksumSigstoreFile)

	os.WriteFile(checksumPath, checksumData, 0644)
	os.WriteFile(signaturePath, signatureData, 0644)

	t.Run("BothFilesExist", func(t *testing.T) {
		err := cosign.ValidateChecksumFilesExist(checksumPath, signaturePath)
		if err != nil {
			t.Errorf("Expected validation to succeed, got error: %v", err)
		}
	})

	t.Run("ChecksumFileMissing", func(t *testing.T) {
		err := cosign.ValidateChecksumFilesExist("nonexistent.txt", signaturePath)
		if err == nil {
			t.Fatal("Expected validation to fail with missing checksum file")
		}
		if !contains(err.Error(), "checksums file not found") {
			t.Errorf("Expected error about checksums file not found, got: %v", err)
		}
	})

	t.Run("SignatureFileMissing", func(t *testing.T) {
		err := cosign.ValidateChecksumFilesExist(checksumPath, "nonexistent.json")
		if err == nil {
			t.Fatal("Expected validation to fail with missing signature file")
		}
		if !contains(err.Error(), "signature file not found") {
			t.Errorf("Expected error about signature file not found, got: %v", err)
		}
	})
}

func TestValidateChecksum(t *testing.T) {
	t.Run("ValidChecksum", func(t *testing.T) {
		checksumData, err := testutil.ReadTestFile(testutil.ChecksumFile)
		if err != nil {
			t.Fatalf("Failed to read checksum file: %v", err)
		}
		bundleData, err := testutil.ReadTestFile(testutil.BundleFile)
		if err != nil {
			t.Fatalf("Failed to read bundle file: %v", err)
		}

		err = cosign.ValidateChecksum(checksumData, bundleData, testutil.BundleFile)
		if err != nil {
			t.Errorf("Expected checksum validation to succeed, got error: %v", err)
		}
	})

	t.Run("InvalidChecksum", func(t *testing.T) {
		checksumData, err := testutil.ReadTestFile(testutil.ChecksumFile)
		if err != nil {
			t.Fatalf("Failed to read checksum file: %v", err)
		}

		// Use invalid artifact data
		invalidData := []byte("wrong content\n")

		err = cosign.ValidateChecksum(checksumData, invalidData, testutil.BundleFile)
		if err == nil {
			t.Fatal("Expected checksum validation to fail")
		}
		if !contains(err.Error(), "checksum mismatch") {
			t.Errorf("Expected error about checksum mismatch, got: %v", err)
		}
	})

	t.Run("ArtifactNotInChecksumFile", func(t *testing.T) {
		checksumData, err := testutil.ReadTestFile(testutil.ChecksumFile)
		if err != nil {
			t.Fatalf("Failed to read checksum file: %v", err)
		}

		// Use an artifact name that's not in the checksums file
		someData := []byte("some content\n")

		err = cosign.ValidateChecksum(checksumData, someData, "unknown-artifact.bin")
		if err == nil {
			t.Fatal("Expected checksum validation to fail for unknown artifact")
		}
		if !contains(err.Error(), "not found in checksums data") {
			t.Errorf("Expected error about artifact not found, got: %v", err)
		}
	})
}
