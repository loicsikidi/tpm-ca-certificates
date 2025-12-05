package verify

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/cosign"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spf13/cobra"
)

var (
	checksumsFile      string
	checksumsSignature string
	bundleDate         string
	bundleCommit       string
)

// NewCommand creates the verify command.
//
// The verify command validates the authenticity and integrity of a TPM trust bundle
// using GitHub Attestations and optionally Cosign signatures.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <bundle-file>",
		Short: "verify the authenticity and integrity of a TPM trust bundle",
		Long: `Verify a TPM trust bundle using Sigstore/Cosign and GitHub Attestations.

The verify command performs two types of verification (both required):

1. Cosign Signature Verification (Phase 1):
   - Auto-detects checksums.txt and checksums.txt.sigstore.json locally
   - If not found, downloads them from GitHub release matching the bundle date
   - Verifies Cosign v3 keyless signature
   - Validates checksum matches the bundle
   - Uses Sigstore Public Good infrastructure

2. GitHub Attestation Verification (Phase 2):
   - Fetches attestations from GitHub API
   - Verifies SLSA provenance
   - Validates certificate identity (OIDC issuer, source repository)

Both verifications must succeed for the bundle to be considered valid.`,
		Example: `  # Verify bundle with default settings (date and commit from bundle metadata)
  tpmtb bundle verify tpm-ca-certificates.pem

  # Verify with explicit checksum files
  tpmtb bundle verify tpm-ca-certificates.pem --checksums-file checksums.txt --checksums-signature checksums.txt.sigstore.json

  # Override bundle metadata with explicit date and commit
  tpmtb bundle verify tpm-ca-certificates.pem --date 2025-01-03 --commit a703c9c414fcad56351b5b6326a7d0cbaf2f0b9c`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE:         run,
	}

	cmd.Flags().StringVar(&checksumsFile, "checksums-file", "",
		"Path to checksums.txt file (required, default: auto-detect by searching in the same directory as the bundle)")
	cmd.Flags().StringVar(&checksumsSignature, "checksums-signature", "",
		"Path to checksums.txt.sigstore.json file (required, default: auto-detect by searching in the same directory as the bundle)")
	cmd.Flags().StringVar(&bundleDate, "date", "",
		"Bundle generation date (YYYY-MM-DD) - overrides bundle metadata if specified")
	cmd.Flags().StringVar(&bundleCommit, "commit", "",
		"Git commit hash (40-character hex string) - overrides bundle metadata if specified")

	return cmd
}

type verifiedAttestation struct {
	index  int
	result *verify.VerificationResult
}

func run(cmd *cobra.Command, args []string) error {
	bundlePath := args[0]
	bundleFilename := filepath.Base(bundlePath)

	effectiveDate := bundleDate
	effectiveCommit := bundleCommit

	if (effectiveDate != "" && effectiveCommit == "") || (effectiveDate == "" && effectiveCommit != "") {
		return fmt.Errorf("both --date and --commit flags must be provided together")
	}

	if effectiveDate == "" && effectiveCommit == "" {
		metadata, err := bundle.ParseMetadata(bundlePath)
		if err != nil {
			return fmt.Errorf("failed to parse bundle metadata: %w", err)
		}
		effectiveDate = metadata.Date
		effectiveCommit = metadata.Commit
	}

	displayBundleMetadata(effectiveDate, effectiveCommit)

	digest, err := digest.ComputeSHA256(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to compute digest: %w", err)
	}
	displayDigest(digest, bundleFilename)

	// Handle checksum files auto-detection and download
	effectiveChecksumsFile := checksumsFile
	effectiveChecksumsSignature := checksumsSignature

	if effectiveChecksumsFile == "" && effectiveChecksumsSignature == "" {
		var found bool
		effectiveChecksumsFile, effectiveChecksumsSignature, found = cosign.FindChecksumFiles(bundlePath)
		if !found {
			fmt.Println("Checksum files not found locally, attempting to download from GitHub...")
			effectiveChecksumsFile, effectiveChecksumsSignature, err = downloadChecksumFiles(cmd.Context(), effectiveDate, bundlePath)
			if err != nil {
				return fmt.Errorf("failed to download checksum files: %w", err)
			}
			defer func() {
				os.Remove(effectiveChecksumsFile)      //nolint:errcheck
				os.Remove(effectiveChecksumsSignature) //nolint:errcheck
			}()
		}
	}

	// Create verifier configuration
	cfg := verifier.Config{
		BundlePath:         bundlePath,
		Date:               effectiveDate,
		Commit:             effectiveCommit,
		ChecksumsFile:      effectiveChecksumsFile,
		ChecksumsSignature: effectiveChecksumsSignature,
		SourceRepo:         &github.SourceRepo,
		WorkflowFilename:   github.ReleaseBundleWorkflowPath,
	}

	v, err := verifier.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	displayTitle("Phase 1: Cosign Signature Verification")
	result, err := v.Verify(cmd.Context(), digest)
	if err != nil {
		cli.DisplayError("❌ Verification failed")
		return err
	}

	displayChecksumFiles(result.ChecksumsFile, result.ChecksumsSignature)
	cli.DisplaySuccess("✅ Cosign verification succeeded")

	displayTitle("Phase 2: GitHub Attestation Verification")
	fmt.Printf("Loaded %d attestation(s) from GitHub API\n", len(result.AttestationResults))
	fmt.Println()

	displayPolicyCriteria(v.GetPolicyConfig(), effectiveCommit)

	var verifiedAttestations []verifiedAttestation
	for i, attResult := range result.AttestationResults {
		verifiedAttestations = append(verifiedAttestations, verifiedAttestation{
			index:  i + 1,
			result: attResult,
		})
	}

	displayGithubAttestationSuccess(verifiedAttestations)

	return nil
}

// downloadChecksumFiles downloads checksums.txt and checksums.txt.sigstore.json
// from GitHub release matching the bundle date.
func downloadChecksumFiles(ctx context.Context, releaseTag, bundlePath string) (string, string, error) {
	client := github.NewHTTPClient(nil)

	if err := client.ReleaseExists(ctx, github.SourceRepo, releaseTag); err != nil {
		return "", "", fmt.Errorf("release %s not found: %w", releaseTag, err)
	}

	bundleDir := filepath.Dir(bundlePath)
	checksumsFile := filepath.Join(bundleDir, "checksums.txt")
	checksumsSignature := filepath.Join(bundleDir, "checksums.txt.sigstore.json")

	if err := client.DownloadAsset(ctx, github.SourceRepo, releaseTag, "checksums.txt", checksumsFile); err != nil {
		return "", "", fmt.Errorf("failed to download checksums.txt: %w", err)
	}

	if err := client.DownloadAsset(ctx, github.SourceRepo, releaseTag, "checksums.txt.sigstore.json", checksumsSignature); err != nil {
		os.Remove(checksumsFile) //nolint:errcheck
		return "", "", fmt.Errorf("failed to download checksums.txt.sigstore.json: %w", err)
	}

	fmt.Printf("Downloaded checksum files from release %s\n", releaseTag)
	return checksumsFile, checksumsSignature, nil
}
