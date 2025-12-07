package verify

import (
	"fmt"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/policy"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/api"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

func displayDigest(digest, sourceFile string) {
	fmt.Printf("Loaded digest %s for %s\n", digest, sourceFile)
	fmt.Println()
}

func displaySuccess(result *api.VerifyResult, metadata *bundle.Metadata) {
	cli.DisplaySuccess("✅ Cosign verification succeeded")
	displayPolicyCriteria(result.Policy, metadata.Commit)
	displayGithubAttestationSuccess(result.GithubAttestationResults)
	cli.DisplaySuccess("✅ Bundle verified successfully")
}

func displayGithubAttestationSuccess(verifiedAttestations []*verify.VerificationResult) {
	cli.DisplaySuccess("✅ GitHub verification succeeded")

	fmt.Printf("The following %d attestation(s) matched the policy criteria\n", len(verifiedAttestations))
	fmt.Println()

	for index, va := range verifiedAttestations {
		fmt.Printf("- Attestation #%d\n", index)
		metadata := displayAttestationMetadata(va)
		fmt.Print(metadata)
		fmt.Println()
	}
}

func displayBundleMetadata(metadata *bundle.Metadata) {
	fmt.Println("Bundle Metadata:")
	fmt.Printf("  - Date:   %s\n", metadata.Date)
	fmt.Printf("  - Commit: %s\n", metadata.Commit)
	fmt.Println()
}

func displayPolicyCriteria(cfg policy.Config, commitID string) {
	// Ensure defaults are set for display
	_ = cfg.CheckAndSetDefaults()

	fmt.Println("The following policy criteria will be enforced:")
	fmt.Printf("- Predicate type must match:................ %s\n", cfg.PredicateType)
	fmt.Printf("- Source Repository Owner URI must match:... %s\n", fmt.Sprintf("https://github.com/%s", cfg.SourceRepo.Owner))
	fmt.Printf("- Subject Alternative Name must match regex: %s\n", cfg.BuildSANRegex())
	fmt.Printf("- OIDC Issuer must match:................... %s\n", cfg.OIDCIssuer)
	fmt.Printf("- Build Workflow must match:................ %s\n", cfg.BuildWorkflowRef())
	fmt.Printf("- Git commit ID must match:................. %s\n", commitID)
	fmt.Printf("- Rekor entry date must match:.............. %s\n", cfg.Tag)
	fmt.Println()
}

func displayTitle(title string) {
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
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
