package policy

import (
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// buildCertificateIdentity creates a certificate identity policy for GitHub Actions OIDC.
//
// This function builds a CertificateIdentity that validates:
//   - Subject Alternative Name (SAN) matches the GitHub repository pattern
//   - OIDC Issuer matches GitHub's token service
//   - Build workflow URI matches the expected workflow path and tag
//   - Source repository URI matches the expected repository
//
// The certificate identity is used by both GitHub Attestation and Cosign verification
// to ensure that signatures come from the expected GitHub Actions workflow.
func buildCertificateIdentity(cfg Config) (verify.CertificateIdentity, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("invalid config: %w", err)
	}

	// Build SAN matcher - matches the repository pattern
	sanMatcher, err := verify.NewSANMatcher("", cfg.BuildSANRegex())
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("failed to create SAN matcher: %w", err)
	}

	// Build issuer matcher - exact match for GitHub's OIDC token service
	issuerMatcher, err := verify.NewIssuerMatcher(cfg.OIDCIssuer, "")
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("failed to create issuer matcher: %w", err)
	}

	// Build certificate extensions - validates the workflow and repository URIs
	extensions := certificate.Extensions{
		// BuildSignerURI is the workflow path + ref
		// Format: https://github.com/owner/repo/.github/workflows/workflow.yaml@refs/tags/tag
		BuildSignerURI: cfg.BuildFullWorkflowURI(),

		// SourceRepositoryURI is the repository URL
		SourceRepositoryURI: cfg.BuildSignerRepoURL(),
	}

	// Create certificate identity combining all matchers and extensions
	certID, err := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, extensions)
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("failed to create certificate identity: %w", err)
	}

	return certID, nil
}
