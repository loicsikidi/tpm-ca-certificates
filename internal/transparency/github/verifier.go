package github

import (
	"fmt"

	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/policy"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/verifier"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type Config struct {
	Digest string
	Policy policy.Config
}

func (c *Config) CheckAndSetDefaults() error {
	if err := c.Policy.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid policy config: %w", err)
	}
	if c.Digest == "" {
		return fmt.Errorf("digest cannot be empty")
	}
	return nil
}

// Verifier wraps a Sigstore verifier for attestation verification.
type Verifier struct {
	verifier *verify.Verifier
	policy   verify.PolicyBuilder
}

// NewVerifier creates a new attestation verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid verifier config: %w", err)
	}

	// Create Sigstore verifier with default configuration
	v, err := verifier.New(verifier.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to create sigstore verifier: %w", err)
	}

	policyBuilder, err := policy.BuildAttestationPolicy(cfg.Digest, cfg.Policy)
	if err != nil {
		return nil, fmt.Errorf("failed to build attestation policy: %w", err)
	}

	return &Verifier{
		verifier: v,
		policy:   policyBuilder,
	}, nil
}

// Verify verifies an attestation bundle against a policy.
func (v *Verifier) Verify(att *github.Attestation) (*verify.VerificationResult, error) {
	if att.Bundle == nil {
		return nil, fmt.Errorf("attestation bundle is nil")
	}

	result, err := v.verifier.Verify(att.Bundle, v.policy)
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return result, nil
}
