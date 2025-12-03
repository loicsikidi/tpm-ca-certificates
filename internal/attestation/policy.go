package attestation

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// PolicyOptions contains the criteria for attestation verification.
type PolicyOptions struct {
	// SourceRepo is the GitHub repository in "owner/repo" format
	SourceRepo string

	// OIDCIssuer is the expected OIDC issuer URL
	// Default: https://token.actions.githubusercontent.com
	OIDCIssuer string

	// PredicateType is the expected attestation predicate type
	// Default: https://slsa.dev/provenance/v1
	PredicateType string

	// BuildWorkflow is the expected workflow path
	// Format: .github/workflows/release-bundle.yaml
	BuildWorkflow string

	// Tag is the expected git tag
	// Format: YYYY-MM-DD (e.g., "2025-01-03")
	Tag string
}

// BuildPolicy creates a verification policy from the given options.
//
// The policy enforces:
//   - Artifact digest matches the provided digest
//   - Certificate SAN matches the source repository
//   - OIDC issuer matches the expected issuer
//   - Build workflow and signer repo match the expected workflow ref
//
// Example:
//
//	policy, err := BuildPolicy("sha256:abc123...", PolicyOptions{
//	    SourceRepo:    "loicsikidi/tpm-trust-bundle",
//	    OIDCIssuer:    "https://token.actions.githubusercontent.com",
//	    PredicateType: "https://slsa.dev/provenance/v1",
//	    BuildWorkflow: ".github/workflows/release-bundle.yaml",
//	    Tag:           "2025-01-03",
//	})
func BuildPolicy(digest string, opts PolicyOptions) (*verify.PolicyBuilder, error) {
	// Set defaults
	if opts.OIDCIssuer == "" {
		opts.OIDCIssuer = "https://token.actions.githubusercontent.com"
	}
	if opts.PredicateType == "" {
		opts.PredicateType = "https://slsa.dev/provenance/v1"
	}

	// Parse digest (format: "sha256:HEX")
	digestParts := strings.SplitN(digest, ":", 2)
	if len(digestParts) != 2 {
		return nil, fmt.Errorf("invalid digest format: expected 'sha256:HEX', got %q", digest)
	}
	digestAlg := digestParts[0]
	digestHex := digestParts[1]

	digestBytes, err := hex.DecodeString(digestHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode digest: %w", err)
	}

	// Build artifact digest policy option
	artifactDigestOpt := verify.WithArtifactDigest(digestAlg, digestBytes)

	// Build certificate identity policy
	// SAN regex: ^https://github.com/{owner}/{repo}/
	owner, repo, err := splitRepo(opts.SourceRepo)
	if err != nil {
		return nil, fmt.Errorf("invalid source repository: %w", err)
	}

	sanRegex := fmt.Sprintf("(?i)^https://github.com/%s/%s/", owner, repo)
	sanMatcher, err := verify.NewSANMatcher("", sanRegex)
	if err != nil {
		return nil, fmt.Errorf("failed to create SAN matcher: %w", err)
	}

	// Issuer matcher (exact match)
	issuerMatcher, err := verify.NewIssuerMatcher(opts.OIDCIssuer, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create issuer matcher: %w", err)
	}

	// Build expected workflow ref
	// Format: .github/workflows/release-bundle.yaml@refs/tags/{tag}
	expectedWorkflowRef := fmt.Sprintf("%s@refs/tags/%s", opts.BuildWorkflow, opts.Tag)
	expectedSignerRepo := fmt.Sprintf("https://github.com/%s/%s", owner, repo)

	// Certificate extensions for build workflow validation
	extensions := certificate.Extensions{
		// BuildSignerURI is the workflow path + ref
		// Format: https://github.com/owner/repo/.github/workflows/workflow.yaml@refs/tags/tag
		BuildSignerURI: fmt.Sprintf("%s/%s", expectedSignerRepo, expectedWorkflowRef),

		// SourceRepositoryURI is the repository URL
		SourceRepositoryURI: expectedSignerRepo,
	}

	certID, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, extensions)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate identity: %w", err)
	}

	// Build policy - combine artifact digest and certificate identity
	policy := verify.NewPolicy(artifactDigestOpt, verify.WithCertificateIdentity(certID))

	return &policy, nil
}
