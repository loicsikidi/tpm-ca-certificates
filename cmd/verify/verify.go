package verify

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/attestation"
	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/spf13/cobra"
)

const (
	sourceRepo = "loicsikidi/tpm-ca-certificates"
)

var (
	checksumsFile      string
	checksumsSignature string
	bundleDate         string
	bundleCommit       string
)

type color string

const (
	colorRed   color = "\033[31m"
	colorGreen color = "\033[32m"
	colorReset color = "\033[0m"
)

// NewCommand creates the verify command.
//
// The verify command validates the authenticity and integrity of a TPM trust bundle
// using GitHub Attestations and optionally Cosign signatures.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <bundle-file>",
		Short: "Verify the authenticity and integrity of a TPM trust bundle",
		Long: `Verify a TPM trust bundle using GitHub Attestations and Sigstore/Cosign.

The verify command performs two types of verification:

1. GitHub Attestation (required):
   - Fetches attestations from GitHub API
   - Verifies SLSA provenance
   - Validates certificate identity (OIDC issuer, source repository)

2. Cosign signature (optional):
   - Auto-detects checksums.txt and checksums.txt.sigstore.json
   - Verifies Cosign v3 keyless signature
   - Validates checksum matches the bundle

The command outputs verification results`,
		Example: `  # Verify bundle with default settings (date and commit from bundle metadata)
  tpmtb verify tpm-ca-certificates.pem

  # Verify with explicit checksum files
  tpmtb verify tpm-ca-certificates.pem --checksums-file checksums.txt --checksums-signature checksums.txt.sigstore.json

  # Override bundle metadata with explicit date and commit
  tpmtb verify tpm-ca-certificates.pem --date 2025-01-03 --commit a703c9c414fcad56351b5b6326a7d0cbaf2f0b9c`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE:         run,
	}

	cmd.Flags().StringVar(&checksumsFile, "checksums-file", "",
		"Path to checksums.txt file (default: auto-detect by searching in the same directory as the bundle)")
	cmd.Flags().StringVar(&checksumsSignature, "checksums-signature", "",
		"Path to checksums.txt.sigstore.json file (default: auto-detect by searching in the same directory as the bundle)")
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

	digest, err := attestation.ComputeSHA256(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to compute digest: %w", err)
	}

	fmt.Printf("Loaded digest %s for %s\n", digest, bundleFilename)

	owner, repo, err := splitRepo(sourceRepo)
	if err != nil {
		return fmt.Errorf("invalid source repository: %w", err)
	}

	client := attestation.NewHTTPClient(nil)
	attestations, err := client.GetAttestationsWithContext(cmd.Context(), owner, repo, digest)
	if err != nil {
		fmt.Println(colorize(colorRed, "❌ Failed to fetch attestations from GitHub API"))
		return fmt.Errorf("failed to fetch attestations: %w", err)
	}

	if len(attestations) == 0 {
		return fmt.Errorf("no attestations found for this artifact")
	}

	fmt.Printf("Loaded %d attestation(s) from GitHub API\n", len(attestations))
	fmt.Println()

	displayPolicyCriteria(owner, sourceRepo, effectiveDate)

	verifier, err := attestation.NewVerifier()
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	policyOpts := attestation.PolicyOptions{
		SourceRepo:    sourceRepo,
		BuildWorkflow: ".github/workflows/release-bundle.yaml",
		Tag:           effectiveDate,
	}

	policy, err := attestation.BuildPolicy(digest, policyOpts)
	if err != nil {
		return fmt.Errorf("failed to build policy: %w", err)
	}

	var verifiedAttestations []verifiedAttestation
	var verificationErr error

	for i, att := range attestations {
		result, err := verifier.Verify(att, policy)
		if err != nil {
			verificationErr = fmt.Errorf("attestation %d verification failed: %w", i, err)
			continue
		}

		verifiedAttestations = append(verifiedAttestations, verifiedAttestation{
			index:  i + 1,
			result: result,
		})
	}

	displayBundleMetadata(effectiveDate, effectiveCommit)

	if len(verifiedAttestations) == 0 {
		fmt.Println(colorize(colorRed, "❌ Verification failed"))
		if verificationErr != nil {
			return verificationErr
		}
		return fmt.Errorf("no attestations passed verification")
	}

	displaySuccess(verifiedAttestations)

	return nil
}

func displaySuccess(verifiedAttestations []verifiedAttestation) {
	fmt.Println(colorize(colorGreen, "✅ Verification succeeded"))
	fmt.Println()

	fmt.Printf("The following %d attestation(s) matched the policy criteria\n", len(verifiedAttestations))
	fmt.Println()

	for _, va := range verifiedAttestations {
		fmt.Printf("- Attestation #%d\n", va.index)
		metadata := displayAttestationMetadata(va.result)
		fmt.Print(metadata)
		fmt.Println()
	}
}

func displayBundleMetadata(date, commit string) {
	fmt.Println("Bundle Metadata:")
	fmt.Printf("  - Date:   %s\n", date)
	fmt.Printf("  - Commit: %s\n", commit)
	fmt.Println()
}

func displayPolicyCriteria(owner, sourceRepo, tag string) {
	fmt.Println("The following policy criteria will be enforced:")
	fmt.Printf("- Predicate type must match:................ %s\n", "https://slsa.dev/provenance/v1")
	fmt.Printf("- Source Repository Owner URI must match:... %s\n", fmt.Sprintf("https://github.com/%s", owner))
	fmt.Printf("- Subject Alternative Name must match regex: %s\n", fmt.Sprintf("(?i)^https://github.com/%s/", sourceRepo))
	fmt.Printf("- OIDC Issuer must match:................... %s\n", "https://token.actions.githubusercontent.com")
	fmt.Printf("- Build Workflow must match:................ %s\n", fmt.Sprintf(".github/workflows/release-bundle.yml@refs/tags/%s", tag))
	fmt.Println()
}

// TODO(lsikidi): refactor this ugly function
func displayAttestationMetadata(vr *verify.VerificationResult) string {
	var sb strings.Builder

	fields := vr.Statement.Predicate.GetFields()

	// Extract buildDefinition
	var buildRepo, buildWorkflow, signerWorkflow, gitCommit string

	if buildDef := fields["buildDefinition"]; buildDef != nil {
		buildDefStruct := buildDef.GetStructValue()
		if buildDefStruct != nil {
			buildDefFields := buildDefStruct.GetFields()

			// Extract externalParameters.workflow
			if extParams := buildDefFields["externalParameters"]; extParams != nil {
				extParamsStruct := extParams.GetStructValue()
				if extParamsStruct != nil {
					extParamsFields := extParamsStruct.GetFields()
					if workflow := extParamsFields["workflow"]; workflow != nil {
						workflowStruct := workflow.GetStructValue()
						if workflowStruct != nil {
							workflowFields := workflowStruct.GetFields()

							if repo := workflowFields["repository"]; repo != nil {
								buildRepo = repo.GetStringValue()
							}
							if path := workflowFields["path"]; path != nil {
								buildWorkflow = path.GetStringValue()
							}
							if ref := workflowFields["ref"]; ref != nil {
								buildWorkflow += "@" + ref.GetStringValue()
							}
						}
					}
				}
			}

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

	// Extract runDetails.builder.id for signer workflow
	if runDetails := fields["runDetails"]; runDetails != nil {
		runDetailsStruct := runDetails.GetStructValue()
		if runDetailsStruct != nil {
			runDetailsFields := runDetailsStruct.GetFields()
			if builder := runDetailsFields["builder"]; builder != nil {
				builderStruct := builder.GetStructValue()
				if builderStruct != nil {
					builderFields := builderStruct.GetFields()
					if id := builderFields["id"]; id != nil {
						signerWorkflow = id.GetStringValue()
					}
				}
			}
		}
	}

	// Extract signer repo from signerWorkflow (format: https://github.com/{owner}/{repo}/.github/workflows/...)
	signerRepo := ""
	if signerWorkflow != "" {
		// Parse: https://github.com/{owner}/{repo}/.github/workflows/workflow.yml@ref
		parts := strings.SplitN(signerWorkflow, "/.github/workflows/", 2)
		if len(parts) == 2 {
			signerRepo = parts[0]
			signerWorkflow = ".github/workflows/" + parts[1]
		}
	}

	// Extract Rekor timestamp
	var rekorTimestamp string
	if len(vr.VerifiedTimestamps) > 0 {
		rekorTimestamp = vr.VerifiedTimestamps[0].Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")
	}

	// Build output
	sb.WriteString(fmt.Sprintf("  - Build repo:..... %s\n", buildRepo))
	sb.WriteString(fmt.Sprintf("  - Build workflow:. %s\n", buildWorkflow))
	sb.WriteString(fmt.Sprintf("  - Git commit:..... %s\n", gitCommit))
	sb.WriteString(fmt.Sprintf("  - Signer repo:.... %s\n", signerRepo))
	sb.WriteString(fmt.Sprintf("  - Signer workflow: %s\n", signerWorkflow))
	if rekorTimestamp != "" {
		sb.WriteString(fmt.Sprintf("  - Rekor timestamp: %s\n", rekorTimestamp))
	}

	return sb.String()
}

func splitRepo(repository string) (owner, repo string, err error) {
	parts := strings.SplitN(repository, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repository format: expected 'owner/repo', got %q", repository)
	}
	return parts[0], parts[1], nil
}

func colorize(color color, text string) string {
	return string(color) + text + string(colorReset)
}
