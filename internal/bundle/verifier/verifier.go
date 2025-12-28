package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bundlepkg "github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/cosign"
	transparencyGithub "github.com/loicsikidi/tpm-ca-certificates/internal/transparency/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/policy"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Config contains configuration for bundle verification.
type Config struct {
	// Date is the bundle generation date (YYYY-MM-DD format)
	//
	// Required.
	Date string

	// Commit is the git commit hash (40-character hex string)
	//
	// Required.
	Commit string

	// SourceRepo is the source repository
	//
	// (optional, will use default if nil)
	SourceRepo *github.Repo

	// WorkflowFilename is the GitHub Actions workflow file name
	//
	// Optional, default: [github.ReleaseBundleWorkflowPath]
	WorkflowFilename string

	// HTTPClient is the HTTP client to use for requests.
	//
	// Optional. If nil, it stays nil and default HTTP client will be used.
	HTTPClient utils.HttpClient

	// DisableLocalCache mode allows to work on a read-only
	// files system if this is set, cache path is ignored.
	//
	// Optional. Default is false (local cache enabled).
	DisableLocalCache bool

	// TrustedRoot is the Sigstore trusted root for offline verification.
	//
	// Optional. If provided, this will be used instead of fetching from TUF.
	TrustedRoot []byte
}

// CheckAndSetDefaults validates and sets default values.
func (c *Config) CheckAndSetDefaults() error {
	if c.Date == "" {
		return fmt.Errorf("date cannot be empty")
	}
	if c.Commit == "" {
		return fmt.Errorf("commit cannot be empty")
	}
	if c.SourceRepo == nil {
		c.SourceRepo = &github.Repo{
			Owner: github.SourceRepo.Owner,
			Name:  github.SourceRepo.Name,
		}
	}
	if err := c.SourceRepo.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid source repository: %w", err)
	}
	if c.WorkflowFilename == "" {
		c.WorkflowFilename = github.ReleaseBundleWorkflowPath
	}

	return nil
}

// Verifier handles bundle verification.
type Verifier struct {
	config Config
}

// New creates a new Verifier instance.
func New(cfg Config) (*Verifier, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &Verifier{config: cfg}, nil
}

// VerifyResult contains the results of bundle verification.
type VerifyResult struct {
	// Policy is the policy used for verification
	Policy policy.Config

	// CosignResult is the result from Cosign verification
	CosignResult *verify.VerificationResult

	// GithubAttestationResults contains all verified attestations
	GithubAttestationResults []*verify.VerificationResult
}

// Verify performs full bundle verification (Cosign + GitHub Attestations).
func (v *Verifier) Verify(ctx context.Context, bundleData, checksumsData, checksumsSigData, provenanceData []byte, digest string) (*VerifyResult, error) {
	result := &VerifyResult{Policy: v.GetPolicyConfig()}

	// Phase 1: Cosign verification
	cosignResult, err := v.verifyCosign(ctx, bundleData, checksumsData, checksumsSigData)
	if err != nil {
		return nil, fmt.Errorf("cosign verification failed: %w", err)
	}
	result.CosignResult = cosignResult

	// Phase 2: GitHub Attestation verification
	attestationResults, err := v.verifyGitHubAttestations(ctx, provenanceData, digest)
	if err != nil {
		return nil, fmt.Errorf("github attestation verification failed: %w", err)
	}
	result.GithubAttestationResults = attestationResults

	return result, nil
}

func (v *Verifier) GetPolicyConfig() policy.Config {
	return policy.Config{
		SourceRepo:    v.config.SourceRepo,
		BuildWorkflow: v.config.WorkflowFilename,
		Tag:           v.config.Date,
	}
}

func (v *Verifier) GetSigstoreVerifierConfig() (verifier.Config, error) {
	cfg := verifier.Config{}

	// Priority 1: Use custom trusted root if provided (offline mode)
	if len(v.config.TrustedRoot) > 0 {
		trustedRoot, err := LoadTrustedRoot(v.config.TrustedRoot)
		if err != nil {
			return cfg, fmt.Errorf("failed to load custom trusted root: %w", err)
		}
		cfg.Root = trustedRoot
		return cfg, nil
	}

	// Priority 2: Fetch from TUF with local cache disabled
	if v.config.DisableLocalCache {
		opts := verifier.GetDefaultTUFOptions(v.config.HTTPClient)
		opts.DisableLocalCache = true
		trustedRoot, err := root.FetchTrustedRootWithOptions(opts)
		if err != nil {
			return cfg, err
		}
		cfg.Root = trustedRoot
	}

	// Priority 3: Use default (fetch from TUF with local cache enabled)
	return cfg, nil
}

// verifyCosign performs Cosign signature verification.
func (v *Verifier) verifyCosign(ctx context.Context, bundleData, checksumsData, checksumsSigData []byte) (*verify.VerificationResult, error) {
	verifierCfg, err := v.GetSigstoreVerifierConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to produce sigstore verifier config: %w", err)
	}
	metadata, err := bundlepkg.ParseMetadata(bundleData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bundle metadata: %w", err)
	}
	bundleFilename := bundlepkg.FilenamebyBundleType[metadata.Type]
	result, err := cosign.VerifyChecksum(ctx, v.GetPolicyConfig(), verifierCfg, checksumsData, checksumsSigData, bundleData, bundleFilename)
	if err != nil {
		return nil, err
	}

	if err := verifyCosignCommit(result, v.config.Commit); err != nil {
		return nil, fmt.Errorf("commit verification failed: %w", err)
	}

	if err := verifyRekorTimestampDate(result, v.config.Date); err != nil {
		return nil, err
	}

	return result, nil
}

// verifyGitHubAttestations performs GitHub Attestation verification.
func (v *Verifier) verifyGitHubAttestations(_ context.Context, provenanceData []byte, digest string) ([]*verify.VerificationResult, error) {
	// Unmarshal the provenance data (attestation)
	var bundle bundle.Bundle
	if err := json.Unmarshal(provenanceData, &bundle); err != nil {
		return nil, fmt.Errorf("failed to unmarshal provenance: %w", err)
	}

	verifierCfg, err := v.GetSigstoreVerifierConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to produce sigstore verifier config: %w", err)
	}
	cfg := transparencyGithub.Config{
		Digest:   digest,
		Policy:   v.GetPolicyConfig(),
		Verifier: verifierCfg,
	}

	verifier, err := transparencyGithub.NewVerifier(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create github verifier: %w", err)
	}

	// Verify the attestation
	result, err := verifier.Verify(&bundle)
	if err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}

	// Verify Rekor timestamp matches the bundle date
	if err := verifyRekorTimestampDate(result, v.config.Date); err != nil {
		return nil, fmt.Errorf("timestamp validation failed: %w", err)
	}

	// Verify commit matches the expected commit
	if err := verifyAttestationCommit(result, v.config.Commit); err != nil {
		return nil, fmt.Errorf("commit validation failed: %w", err)
	}

	return []*verify.VerificationResult{result}, nil
}

// verifyRekorTimestampDate validates that the Rekor timestamp date matches the expected tag date.
func verifyRekorTimestampDate(result *verify.VerificationResult, expectedDate string) error {
	if len(result.VerifiedTimestamps) == 0 {
		return fmt.Errorf("no verified timestamps found in attestation")
	}

	// Get the first Rekor timestamp
	rekorTimestamp := result.VerifiedTimestamps[0].Timestamp

	// Extract date from timestamp (YYYY-MM-DD format)
	actualDate := rekorTimestamp.UTC().Format("2006-01-02")

	// Compare dates
	if actualDate != expectedDate {
		return fmt.Errorf("date mismatch between tag and Rekor entry: expected %s, got %s (full timestamp: %s)",
			expectedDate, actualDate, rekorTimestamp.UTC().Format(time.RFC3339))
	}

	return nil
}

// verifyAttestationCommit validates that the git commit in the attestation matches the expected commit.
func verifyAttestationCommit(result *verify.VerificationResult, expectedCommit string) error {
	if result.Statement == nil || result.Statement.Predicate == nil {
		return fmt.Errorf("attestation has no statement or predicate")
	}

	fields := result.Statement.Predicate.GetFields()

	// Extract buildDefinition.resolvedDependencies[0].digest.gitCommit
	var gitCommit string
	if buildDef := fields["buildDefinition"]; buildDef != nil {
		buildDefStruct := buildDef.GetStructValue()
		if buildDefStruct != nil {
			buildDefFields := buildDefStruct.GetFields()

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

	if gitCommit == "" {
		return fmt.Errorf("git commit not found in attestation")
	}

	// Compare commits (case-insensitive)
	if !strings.EqualFold(gitCommit, expectedCommit) {
		return fmt.Errorf("commit mismatch: expected %s, got %s", expectedCommit, gitCommit)
	}

	return nil
}

// verifyCosignCommit validates that the git commit in the Cosign certificate matches the expected commit.
func verifyCosignCommit(result *verify.VerificationResult, expectedCommit string) error {
	if result.Signature == nil || result.Signature.Certificate == nil {
		return fmt.Errorf("no certificate found in verification result")
	}

	cert := result.Signature.Certificate

	gitCommit := cert.SourceRepositoryDigest
	if gitCommit == "" {
		return fmt.Errorf("git commit not found in certificate extensions")
	}

	// Compare commits (case-insensitive)
	if !strings.EqualFold(gitCommit, expectedCommit) {
		return fmt.Errorf("commit mismatch: expected %s, got %s", expectedCommit, gitCommit)
	}

	return nil
}
