package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/cosign"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/policy"
)

// contains checks if a string contains a substring.
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// testPolicyConfig returns a valid policy.Config for testing purposes.
func testPolicyConfig() policy.Config {
	return policy.Config{
		SourceRepo:    &github.SourceRepo,
		OIDCIssuer:    "https://token.actions.githubusercontent.com",
		BuildWorkflow: github.ReleaseBundleWorkflowPath,
		Tag:           "2025-12-03",
	}
}

func TestCosignVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	cfg := testPolicyConfig()

	testdataDir := "testdata"
	bundlePath := filepath.Join(testdataDir, "tpm-ca-certificates.pem")
	checksumPath := filepath.Join(testdataDir, "checksums.txt")
	signaturePath := filepath.Join(testdataDir, "checksums.txt.sigstore.json")

	t.Run("VerifyValidSignature", func(t *testing.T) {
		checksumData, err := os.ReadFile(checksumPath)
		if err != nil {
			t.Fatalf("Failed to read checksum file: %v", err)
		}
		signatureData, err := os.ReadFile(signaturePath)
		if err != nil {
			t.Fatalf("Failed to read signature file: %v", err)
		}
		bundleData, err := os.ReadFile(bundlePath)
		if err != nil {
			t.Fatalf("Failed to read bundle file: %v", err)
		}

		result, err := cosign.VerifyChecksum(ctx, cfg, checksumData, signatureData, bundleData, "tpm-ca-certificates.pem")
		if err != nil {
			t.Fatalf("Expected successful verification, got error: %v", err)
		}
		if result == nil {
			t.Fatal("Expected non-nil verification result")
		}
	})

	t.Run("VerifyInvalidChecksum", func(t *testing.T) {
		checksumData, err := os.ReadFile(checksumPath)
		if err != nil {
			t.Fatalf("Failed to read checksum file: %v", err)
		}
		signatureData, err := os.ReadFile(signaturePath)
		if err != nil {
			t.Fatalf("Failed to read signature file: %v", err)
		}

		// Create invalid bundle data
		invalidData := []byte("invalid content\n")

		// Verification should fail because checksum doesn't match
		_, err = cosign.VerifyChecksum(ctx, cfg, checksumData, signatureData, invalidData, "tpm-ca-certificates.pem")
		if err == nil {
			t.Fatal("Expected verification to fail with invalid checksum, but it succeeded")
		}
		if !contains(err.Error(), "checksum mismatch") {
			t.Errorf("Expected error about checksum mismatch, got: %v", err)
		}
	})

	t.Run("VerifyInvalidSignatureData", func(t *testing.T) {
		checksumData, err := os.ReadFile(checksumPath)
		if err != nil {
			t.Fatalf("Failed to read checksum file: %v", err)
		}
		bundleData, err := os.ReadFile(bundlePath)
		if err != nil {
			t.Fatalf("Failed to read bundle file: %v", err)
		}

		// Use invalid signature data
		invalidSignature := []byte("invalid json")

		_, err = cosign.VerifyChecksum(ctx, cfg, checksumData, invalidSignature, bundleData, "tpm-ca-certificates.pem")
		if err == nil {
			t.Fatal("Expected verification to fail with invalid signature data, but it succeeded")
		}
		if !contains(err.Error(), "failed to load signature bundle") {
			t.Errorf("Expected error about loading signature bundle, got: %v", err)
		}
	})
}

func TestFindChecksumFiles(t *testing.T) {
	testdataDir := "testdata"
	bundlePath := filepath.Join(testdataDir, "tpm-ca-certificates.pem")

	t.Run("AutoDetectSuccess", func(t *testing.T) {
		checksumPath, signaturePath, found := cosign.FindChecksumFiles(bundlePath)
		if !found {
			t.Fatal("Expected to find checksum files, but none were found")
		}

		expectedChecksumPath := filepath.Join(testdataDir, "checksums.txt")
		expectedSignaturePath := filepath.Join(testdataDir, "checksums.txt.sigstore.json")

		if checksumPath != expectedChecksumPath {
			t.Errorf("Expected checksums path %s, got %s", expectedChecksumPath, checksumPath)
		}
		if signaturePath != expectedSignaturePath {
			t.Errorf("Expected signature path %s, got %s", expectedSignaturePath, signaturePath)
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
	testdataDir := "testdata"
	checksumPath := filepath.Join(testdataDir, "checksums.txt")
	signaturePath := filepath.Join(testdataDir, "checksums.txt.sigstore.json")

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
	testdataDir := "testdata"
	bundlePath := filepath.Join(testdataDir, "tpm-ca-certificates.pem")
	checksumPath := filepath.Join(testdataDir, "checksums.txt")

	t.Run("ValidChecksum", func(t *testing.T) {
		checksumData, err := os.ReadFile(checksumPath)
		if err != nil {
			t.Fatalf("Failed to read checksum file: %v", err)
		}
		bundleData, err := os.ReadFile(bundlePath)
		if err != nil {
			t.Fatalf("Failed to read bundle file: %v", err)
		}

		err = cosign.ValidateChecksum(checksumData, bundleData, "tpm-ca-certificates.pem")
		if err != nil {
			t.Errorf("Expected checksum validation to succeed, got error: %v", err)
		}
	})

	t.Run("InvalidChecksum", func(t *testing.T) {
		checksumData, err := os.ReadFile(checksumPath)
		if err != nil {
			t.Fatalf("Failed to read checksum file: %v", err)
		}

		// Use invalid artifact data
		invalidData := []byte("wrong content\n")

		err = cosign.ValidateChecksum(checksumData, invalidData, "tpm-ca-certificates.pem")
		if err == nil {
			t.Fatal("Expected checksum validation to fail")
		}
		if !contains(err.Error(), "checksum mismatch") {
			t.Errorf("Expected error about checksum mismatch, got: %v", err)
		}
	})

	t.Run("ArtifactNotInChecksumFile", func(t *testing.T) {
		checksumData, err := os.ReadFile(checksumPath)
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
