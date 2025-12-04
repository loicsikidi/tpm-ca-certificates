package policy

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/verify"
)

// BuildAttestationPolicy creates a verification policy for GitHub Attestations.
//
// This function builds a PolicyBuilder that validates:
//   - Artifact digest matches the provided digest
//   - Certificate identity (via BuildCertificateIdentity)
//
// The digest must be in the format "algorithm:hex" (e.g., "sha256:abc123...").
//
// Example:
//
//	policy, err := BuildAttestationPolicy("sha256:abc123...", Config{
//	    SourceRepo:    "loicsikidi/tpm-ca-certificates",
//	    BuildWorkflow: ".github/workflows/release-bundle.yaml",
//	    Tag:           "2025-12-03",
//	})
func BuildAttestationPolicy(digest string, cfg Config) (verify.PolicyBuilder, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return verify.PolicyBuilder{}, fmt.Errorf("invalid config: %w", err)
	}

	// Parse digest (format: "sha256:HEX")
	digestParts := strings.SplitN(digest, ":", 2)
	if len(digestParts) != 2 {
		return verify.PolicyBuilder{}, fmt.Errorf("invalid digest format: expected 'algorithm:hex', got %q", digest)
	}
	digestAlg := digestParts[0]
	digestHex := digestParts[1]

	digestBytes, err := hex.DecodeString(digestHex)
	if err != nil {
		return verify.PolicyBuilder{}, fmt.Errorf("failed to decode digest hex: %w", err)
	}

	// Build artifact digest policy option
	artifactDigestOpt := verify.WithArtifactDigest(digestAlg, digestBytes)

	// Build certificate identity policy
	certID, err := buildCertificateIdentity(cfg)
	if err != nil {
		return verify.PolicyBuilder{}, err
	}

	// Build policy - combine artifact digest and certificate identity
	policy := verify.NewPolicy(artifactDigestOpt, verify.WithCertificateIdentity(certID))

	return policy, nil
}
