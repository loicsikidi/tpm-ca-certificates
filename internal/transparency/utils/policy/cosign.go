package policy

import (
	"fmt"
	"io"

	"github.com/sigstore/sigstore-go/pkg/verify"
)

// BuildCosignPolicy creates a verification policy for Cosign blob signing.
//
// This function builds a Policy that validates:
//   - Artifact content (via io.Reader)
//   - Certificate identity (via BuildCertificateIdentity)
//
// The artifact reader should provide access to the file being verified (e.g., checksums.txt).
//
// Example:
//
//	file, err := os.Open("checksums.txt")
//	if err != nil {
//	    return err
//	}
//	defer file.Close()
//
//	policy, err := BuildCosignPolicy(file, Config{
//	    SourceRepo:    "loicsikidi/tpm-ca-certificates",
//	    BuildWorkflow: ".github/workflows/release-bundle.yaml",
//	    Tag:           "2025-12-03",
//	})
func BuildCosignPolicy(artifact io.Reader, cfg Config) (verify.PolicyBuilder, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return verify.PolicyBuilder{}, fmt.Errorf("invalid config: %w", err)
	}

	// Build artifact policy - Cosign verifies the artifact directly
	// (not by digest) because ED25519 signatures require the full artifact content
	artifactPolicy := verify.WithArtifact(artifact)

	// Build certificate identity policy
	certID, err := buildCertificateIdentity(cfg)
	if err != nil {
		return verify.PolicyBuilder{}, err
	}

	// Build policy - combine artifact and certificate identity
	policy := verify.NewPolicy(artifactPolicy, verify.WithCertificateIdentity(certID))

	return policy, nil
}
