package cosign

import (
	"bytes"
	"context"
	"fmt"

	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/policy"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/verifier"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// VerifyChecksum verifies the Cosign signature of a checksum file and validates
// that the artifact's checksum matches the one in the checksums file.
//
// It performs the following steps:
//  1. Loads the Sigstore bundle from the signature file
//  2. Verifies the signature using the keyless Cosign workflow (SCT + transparency log + observer timestamps)
//  3. Validates the certificate identity (OIDC issuer, workflow path) using shared policy
//  4. Parses the checksums file to extract the expected checksum for the artifact
//  5. Computes the actual checksum of the artifact and compares it
//
// Returns the verification result which contains certificate extensions with commit information.
func VerifyChecksum(ctx context.Context, policyCfg policy.Config, verifierCfg verifier.Config, checksumData, signatureData, artifactData []byte, artifactName string) (*verify.VerificationResult, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(signatureData); err != nil {
		return nil, fmt.Errorf("failed to load signature bundle: %w", err)
	}

	sgVerifier, err := verifier.New(verifierCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	policyBuilder, err := policy.BuildCosignPolicy(bytes.NewReader(checksumData), policyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build policy: %w", err)
	}

	result, err := sgVerifier.Verify(&b, policyBuilder)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Now verify that the artifact's checksum matches the one in the checksums file
	if err := ValidateChecksum(checksumData, artifactData, artifactName); err != nil {
		return nil, fmt.Errorf("checksum validation failed: %w", err)
	}

	return result, nil
}
