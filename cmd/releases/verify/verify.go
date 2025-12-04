package verify

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/cosign"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/policy"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spf13/cobra"
)

const (
	sourceRepo       = "loicsikidi/tpm-ca-certificates"
	workflowFilename = ".github/workflows/release-bundle.yaml"
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
		Short: "Verify the authenticity and integrity of a TPM trust bundle",
		Long: `Verify a TPM trust bundle using Sigstore/Cosign and GitHub Attestations.

The verify command performs two types of verification (both required):

1. Cosign Signature Verification (Phase 1):
   - Auto-detects checksums.txt and checksums.txt.sigstore.json
   - Verifies Cosign v3 keyless signature
   - Validates checksum matches the bundle
   - Uses Sigstore Public Good infrastructure

2. GitHub Attestation Verification (Phase 2):
   - Fetches attestations from GitHub API
   - Verifies SLSA provenance
   - Validates certificate identity (OIDC issuer, source repository)

Both verifications must succeed for the bundle to be considered valid.`,
		Example: `  # Verify bundle with default settings (date and commit from bundle metadata)
  tpmtb releases verify tpm-ca-certificates.pem

  # Verify with explicit checksum files
  tpmtb releases verify tpm-ca-certificates.pem --checksums-file checksums.txt --checksums-signature checksums.txt.sigstore.json

  # Override bundle metadata with explicit date and commit
  tpmtb releases verify tpm-ca-certificates.pem --date 2025-01-03 --commit a703c9c414fcad56351b5b6326a7d0cbaf2f0b9c`,
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

	displayTitle("Phase 1: Cosign Signature Verification")
	if err := cosignCheck(cmd.Context(), bundlePath, effectiveDate, effectiveCommit, checksumsFile, checksumsSignature); err != nil {
		return err
	}

	displayTitle("Phase 2: GitHub Attestation Verification")
	if err := githubAttestationCheck(cmd.Context(), digest, sourceRepo, effectiveDate, effectiveCommit); err != nil {
		return err
	}
	return nil
}

func cosignCheck(ctx context.Context, bundlePath, bundleDate, bundleCommit, checksumsFile, checksumsSignature string) error {
	if checksumsFile == "" && checksumsSignature == "" {
		var found bool
		checksumsFile, checksumsSignature, found = cosign.FindChecksumFiles(bundlePath)
		if !found {
			displayCosignMissingChecksumFilesErr(bundlePath)
			return fmt.Errorf("checksum files not found")
		}
	} else {
		// If one is provided but not the other, error out
		if checksumsFile == "" || checksumsSignature == "" {
			return fmt.Errorf("both --checksums-file and --checksums-signature must be provided together")
		}
		if err := cosign.ValidateChecksumFilesExist(checksumsFile, checksumsSignature); err != nil {
			return err
		}
	}

	displayChecksumFiles(checksumsFile, checksumsSignature)

	policyCfg := policy.Config{
		SourceRepo:    sourceRepo,
		BuildWorkflow: workflowFilename,
		Tag:           bundleDate,
	}
	result, err := cosign.VerifyChecksum(ctx, policyCfg, checksumsFile, checksumsSignature, bundlePath)
	if err != nil {
		displayError("❌ Cosign verification failed")
		return fmt.Errorf("cosign verification failed: %w", err)
	}

	// Verify commit matches the expected commit
	if err := verifyCosignCommit(result, bundleCommit); err != nil {
		displayError("❌ Cosign commit verification failed")
		return fmt.Errorf("cosign commit verification failed: %w", err)
	}

	displaySuccess("✅ Cosign verification succeeded")
	return nil
}

func githubAttestationCheck(ctx context.Context, digest, sourceRepo, date, expectedCommit string) error {
	owner, repo, err := splitRepo(sourceRepo)
	if err != nil {
		return fmt.Errorf("invalid source repository: %w", err)
	}

	client := github.NewHTTPClient(nil)
	attestations, err := client.GetAttestationsWithContext(ctx, owner, repo, digest)
	if err != nil {
		displayError("❌ Failed to fetch attestations from GitHub API")
		return fmt.Errorf("failed to fetch attestations: %w", err)
	}

	if len(attestations) == 0 {
		return fmt.Errorf("no attestations found for this artifact")
	}

	fmt.Printf("Loaded %d attestation(s) from GitHub API\n", len(attestations))
	fmt.Println()

	policyCfg := policy.Config{
		SourceRepo:    sourceRepo,
		BuildWorkflow: workflowFilename,
		Tag:           date,
	}

	displayPolicyCriteria(policyCfg)

	cfg := github.Config{
		Digest: digest,
		Policy: policyCfg,
	}

	verifier, err := github.NewVerifier(cfg)
	if err != nil {
		return fmt.Errorf("failed to github verifier: %w", err)
	}

	var verifiedAttestations []verifiedAttestation
	var verificationErr error

	for i, att := range attestations {
		result, err := verifier.Verify(att)
		if err != nil {
			verificationErr = fmt.Errorf("attestation %d verification failed: %w", i, err)
			continue
		}

		// Verify Rekor timestamp matches the bundle date
		if err := verifyRekorTimestampDate(result, date); err != nil {
			verificationErr = fmt.Errorf("attestation %d timestamp validation failed: %w", i, err)
			continue
		}

		// Verify commit matches the expected commit
		if err := verifyAttestationCommit(result, expectedCommit); err != nil {
			verificationErr = fmt.Errorf("attestation %d commit validation failed: %w", i, err)
			continue
		}

		verifiedAttestations = append(verifiedAttestations, verifiedAttestation{
			index:  i + 1,
			result: result,
		})
	}

	if len(verifiedAttestations) == 0 {
		displayError("❌ Verification failed")
		if verificationErr != nil {
			return verificationErr
		}
		return fmt.Errorf("no attestations passed verification")
	}

	displayGithubAttestationSuccess(verifiedAttestations)
	return nil
}

func splitRepo(repository string) (owner, repo string, err error) {
	parts := strings.SplitN(repository, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repository format: expected 'owner/repo', got %q", repository)
	}
	return parts[0], parts[1], nil
}

// verifyRekorTimestampDate validates that the Rekor timestamp date matches the expected tag date.
func verifyRekorTimestampDate(result *verify.VerificationResult, expectedDate string) error {
	if len(result.VerifiedTimestamps) == 0 {
		return fmt.Errorf("no verified timestamps found in attestation")
	}

	// Get the first Rekor timestamp
	rekorTimestamp := result.VerifiedTimestamps[0].Timestamp

	// Extract date from timestamp (YYYY-MM-DD format)
	actualDate := rekorTimestamp.UTC().Format("2006-01-02")

	// Compare dates
	if actualDate != expectedDate {
		return fmt.Errorf("date mismatch between tag and Rekor entry: expected %s, got %s (full timestamp: %s)",
			expectedDate, actualDate, rekorTimestamp.UTC().Format(time.RFC3339))
	}

	return nil
}

// verifyAttestationCommit validates that the git commit in the attestation matches the expected commit.
func verifyAttestationCommit(result *verify.VerificationResult, expectedCommit string) error {
	if result.Statement == nil || result.Statement.Predicate == nil {
		return fmt.Errorf("attestation has no statement or predicate")
	}

	fields := result.Statement.Predicate.GetFields()

	// Extract buildDefinition.resolvedDependencies[0].digest.gitCommit
	var gitCommit string
	if buildDef := fields["buildDefinition"]; buildDef != nil {
		buildDefStruct := buildDef.GetStructValue()
		if buildDefStruct != nil {
			buildDefFields := buildDefStruct.GetFields()

			// Extract resolvedDependencies[0].digest.gitCommit
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
										gitCommit = commit.GetStringValue()
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if gitCommit == "" {
		return fmt.Errorf("git commit not found in attestation")
	}

	// Compare commits (case-insensitive)
	if !strings.EqualFold(gitCommit, expectedCommit) {
		return fmt.Errorf("commit mismatch: expected %s, got %s", expectedCommit, gitCommit)
	}

	return nil
}

// verifyCosignCommit validates that the git commit in the Cosign certificate matches the expected commit.
func verifyCosignCommit(result *verify.VerificationResult, expectedCommit string) error {
	if result.Signature == nil || result.Signature.Certificate == nil {
		return fmt.Errorf("no certificate found in verification result")
	}

	cert := result.Signature.Certificate

	// Try to extract commit from SourceRepositoryDigest (new field)
	var gitCommit string
	if cert.SourceRepositoryDigest != "" {
		gitCommit = cert.SourceRepositoryDigest
	} else if cert.GithubWorkflowSHA != "" {
		// Fallback to deprecated field
		gitCommit = cert.GithubWorkflowSHA
	}

	if gitCommit == "" {
		return fmt.Errorf("git commit not found in certificate extensions")
	}

	// Compare commits (case-insensitive)
	if !strings.EqualFold(gitCommit, expectedCommit) {
		return fmt.Errorf("commit mismatch: expected %s, got %s", expectedCommit, gitCommit)
	}

	return nil
}
