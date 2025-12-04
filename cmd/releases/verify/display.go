package verify

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/policy"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type color string

const (
	colorRed    color = "\033[31m"
	colorGreen  color = "\033[32m"
	colorYellow color = "\033[33m"
	colorReset  color = "\033[0m"
)

func colorize(color color, text string) string {
	return string(color) + text + string(colorReset)
}

func displayDigest(digest, sourceFile string) {
	fmt.Printf("Loaded digest %s for %s\n", digest, sourceFile)
	fmt.Println()
}

func displaySuccess(msg string) {
	fmt.Println(colorize(colorGreen, msg))
	fmt.Println()
}
func displayError(msg string) {
	fmt.Println(colorize(colorRed, msg))
	fmt.Println()
}

func displayChecksumFiles(checksumsFile, checksumsSignature string) {
	fmt.Printf("Checksums file: %s\n", checksumsFile)
	fmt.Printf("Signature file: %s\n", checksumsSignature)
	fmt.Println()

}
func displayGithubAttestationSuccess(verifiedAttestations []verifiedAttestation) {
	displaySuccess("✅ GitHub verification succeeded")

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

func displayPolicyCriteria(cfg policy.Config) {
	// Ensure defaults are set for display
	_ = cfg.CheckAndSetDefaults()

	owner, _, _ := cfg.SplitRepo()

	fmt.Println("The following policy criteria will be enforced:")
	fmt.Printf("- Predicate type must match:................ %s\n", cfg.PredicateType)
	fmt.Printf("- Source Repository Owner URI must match:... %s\n", fmt.Sprintf("https://github.com/%s", owner))
	fmt.Printf("- Subject Alternative Name must match regex: %s\n", cfg.BuildSANRegex())
	fmt.Printf("- OIDC Issuer must match:................... %s\n", cfg.OIDCIssuer)
	fmt.Printf("- Build Workflow must match:................ %s\n", cfg.BuildWorkflowRef())
	fmt.Println()
}

func displayCosignMissingChecksumFilesErr(bundlePath string) {
	fmt.Println(colorize(colorRed, "❌ Cosign verification failed"))
	fmt.Println()
	fmt.Println("Error: Required checksum files not found")
	fmt.Println("Auto-detection looked for:")
	fmt.Printf("  - %s\n", filepath.Join(filepath.Dir(bundlePath), "checksums.txt"))
	fmt.Printf("  - %s\n", filepath.Join(filepath.Dir(bundlePath), "checksums.txt.sigstore.json"))
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
