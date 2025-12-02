package attestation

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	// Target file containing the trusted root
	trustedRootTarget = "trusted_root.json"
)

// Verifier wraps a Sigstore verifier for attestation verification.
type Verifier struct {
	verifier *verify.Verifier
}

// NewVerifier creates a new attestation verifier.
//
// The verifier is initialized with the GitHub TUF trusted root, which is
// downloaded dynamically from https://tuf.github.com/attestations.
//
// Note: Future improvement - store the initial root in a config file and use
// sync.Once for thread-safe initialization.
func NewVerifier() (*Verifier, error) {
	// Initialize GitHub TUF client
	tufClient, err := initGitHubTUF()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize TUF client: %w", err)
	}

	// Get trusted root from TUF
	trustedRoot, err := getTrustedRoot(tufClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted root: %w", err)
	}

	// Create Sigstore verifier
	// For GitHub attestations, we use transparency log verification
	sigstoreVerifier, err := verify.NewVerifier(
		trustedRoot,
		verify.WithTransparencyLog(1),             // Require transparency log entry
		verify.WithObserverTimestamps(1),          // Use observer timestamps from Rekor
		verify.WithSignedCertificateTimestamps(1), // Require valid SCT (Signed Certificate Timestamp)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	return &Verifier{
		verifier: sigstoreVerifier,
	}, nil
}

// Verify verifies an attestation bundle against a policy.
func (v *Verifier) Verify(att *Attestation, policy *verify.PolicyBuilder) (*verify.VerificationResult, error) {
	if att.Bundle == nil {
		return nil, fmt.Errorf("attestation bundle is nil")
	}

	result, err := v.verifier.Verify(att.Bundle, *policy)
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return result, nil
}

// initGitHubTUF initializes a TUF client for GitHub attestations.
//
// The client downloads metadata from the Sigstore public good instance and
// caches it locally in ~/.tpmtb/tuf-cache.
func initGitHubTUF() (*tuf.Client, error) {
	// Determine cache path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	cachePath := filepath.Join(homeDir, ".tpmtb", "tuf-cache")

	// Create cache directory if it doesn't exist
	if err := os.MkdirAll(cachePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Use default Sigstore TUF configuration
	opts := tuf.DefaultOptions()
	opts.CachePath = cachePath

	client, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}

	return client, nil
}

// getTrustedRoot fetches the trusted root from TUF.
func getTrustedRoot(tufClient *tuf.Client) (*root.TrustedRoot, error) {
	// Download the trusted root target
	trustedRootBytes, err := tufClient.GetTarget(trustedRootTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to download trusted root: %w", err)
	}

	// Parse trusted root
	trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trusted root: %w", err)
	}

	return trustedRoot, nil
}
