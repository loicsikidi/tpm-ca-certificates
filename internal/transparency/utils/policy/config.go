package policy

import (
	"fmt"

	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
)

// Config contains the common criteria for verification (GitHub Attestation and Cosign).
//
// It centralizes the security policy for both verification methods to ensure
// consistency across different verification types.
type Config struct {
	// SourceRepo is the GitHub repository.
	//
	// Required.
	SourceRepo *github.Repo

	// OIDCIssuer is the expected OIDC issuer URL
	// Default: https://token.actions.githubusercontent.com
	OIDCIssuer string

	// PredicateType is the expected attestation predicate type (GitHub Attestation only)
	//
	// Default: https://slsa.dev/provenance/v1
	PredicateType string

	// BuildWorkflow is the expected workflow path
	// Format: .github/workflows/release-bundle.yaml
	//
	// Required.
	BuildWorkflow string

	// Tag is the expected git tag
	// Format: YYYY-MM-DD (e.g., "2025-12-03")
	//
	// Required.
	Tag string
}

// CheckAndSetDefaults validates the config and sets default values.
func (c *Config) CheckAndSetDefaults() error {
	if c.SourceRepo == nil {
		return fmt.Errorf("invalid input: 'SourceRepo' is required")
	}
	if err := c.SourceRepo.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid input: 'SourceRepo' is invalid: %w", err)
	}

	if c.BuildWorkflow == "" {
		return fmt.Errorf("invalid input: 'BuildWorkflow' is required")
	}

	if c.Tag == "" {
		return fmt.Errorf("invalid input: 'Tag' is required")
	}

	// Set defaults
	if c.OIDCIssuer == "" {
		c.OIDCIssuer = "https://token.actions.githubusercontent.com"
	}

	if c.PredicateType == "" {
		c.PredicateType = "https://slsa.dev/provenance/v1"
	}
	return nil
}

// BuildWorkflowRef returns the full workflow reference including the tag.
//
// Format: .github/workflows/release-bundle.yaml@refs/tags/2025-12-03
func (c *Config) BuildWorkflowRef() string {
	return fmt.Sprintf("%s@refs/tags/%s", c.BuildWorkflow, c.Tag)
}

// BuildSignerRepoURL returns the signer repository URL.
//
// Format: https://github.com/{owner}/{repo}
func (c *Config) BuildSignerRepoURL() string {
	return fmt.Sprintf("https://github.com/%s", c.SourceRepo.String())
}

// BuildSANRegex returns the Subject Alternative Name regex pattern.
//
// Format: (?i)^https://github.com/{owner}/{repo}/
func (c *Config) BuildSANRegex() string {
	return fmt.Sprintf("(?i)^https://github.com/%s/", c.SourceRepo.String())
}

// BuildFullWorkflowURI returns the complete workflow URI including repo, path and tag.
//
// Format: https://github.com/{owner}/{repo}/.github/workflows/release-bundle.yaml@refs/tags/2025-12-03
func (c *Config) BuildFullWorkflowURI() string {
	return fmt.Sprintf("%s/%s", c.BuildSignerRepoURL(), c.BuildWorkflowRef())
}
