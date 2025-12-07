package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
)

type VerifyResult = verifier.VerifyResult

var (
	mu         sync.RWMutex
	httpClient = http.DefaultClient // default HTTP client
)

const (
	bundleFilename = "tpm-ca-certificates.pem"
	checksumsFile  = "checksums.txt"
	checksumsSig   = "checksums.txt.sigstore.json"
)

var (
	// ErrBundleNotFound is returned when the requested bundle is not found.
	ErrBundleNotFound = errors.New("trusted bundle not found for the specified date")

	// ErrBundleVerificationFailed is returned when the bundle verification fails.
	ErrBundleVerificationFailed = errors.New("trusted bundle verification failed")
)

// HttpClient returns the current HTTP client used for requests.
func HttpClient() *http.Client {
	mu.RLock()
	defer mu.RUnlock()
	return httpClient
}

// SetHttpClient sets a custom HTTP client for requests.
func SetHttpClient(client *http.Client) {
	mu.Lock()
	defer mu.Unlock()
	httpClient = client
}

// GetConfig configures the bundle retrieval.
type GetConfig struct {
	// Date specifies the bundle release date in YYYY-MM-DD format.
	// If empty, the latest release will be fetched.
	Date string

	// SkipVerify disables bundle verification.
	// When false (default), the bundle will be verified using Cosign and GitHub Attestations.
	SkipVerify bool

	// HTTPClient is the HTTP client to use for requests.
	// If nil, http.DefaultClient will be used.
	HTTPClient *http.Client

	// sourceRepo is the GitHub repository to fetch bundles from.
	//
	// This field is internal for security reasons and should not be set by users.
	sourceRepo *github.Repo
}

// CheckAndSetDefaults validates and sets default values.
func (c *GetConfig) CheckAndSetDefaults() error {
	if c.sourceRepo == nil {
		c.sourceRepo = &github.Repo{
			Owner: github.SourceRepo.Owner,
			Name:  github.SourceRepo.Name,
		}
	}
	if err := c.sourceRepo.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid source repository: %w", err)
	}
	if c.HTTPClient == nil {
		c.HTTPClient = HttpClient()
	}
	return nil
}

// GetRawTrustedBundle retrieves and optionally verifies a TPM trust bundle from GitHub releases.
//
// The function downloads the bundle and its verification artifacts (checksums and signatures)
// entirely in memory, without writing to disk. When verification is enabled (default),
// it performs the same cryptographic verification as the CLI command using both Cosign
// signatures and GitHub Attestations.
//
// Example:
//
//	// Get the latest verified bundle
//	bundleData, err := rot.GetRawTrustedBundle(context.Background(), rot.GetConfig{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get a specific date's bundle without verification
//	bundleData, err = rot.GetRawTrustedBundle(context.Background(), rot.GetConfig{
//	    Date: "2025-12-03",
//	    SkipVerify: true,
//	})
func GetRawTrustedBundle(ctx context.Context, cfg GetConfig) ([]byte, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	client := github.NewHTTPClient(cfg.HTTPClient)

	releaseTag, err := getReleaseTag(ctx, client, cfg)
	if err != nil {
		return nil, err
	}

	bundleData, err := client.DownloadAsset(ctx, *cfg.sourceRepo, releaseTag, bundleFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to download bundle: %w", err)
	}

	// Skip verification if requested
	if cfg.SkipVerify {
		return bundleData, nil
	}

	if _, err := VerifyTrustedBundle(ctx, VerifyConfig{
		Bundle:     bundleData,
		sourceRepo: cfg.sourceRepo,
		HTTPClient: cfg.HTTPClient,
	}); err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return bundleData, nil
}

// getReleaseTag determines which release to fetch.
func getReleaseTag(ctx context.Context, client *github.HTTPClient, cfg GetConfig) (string, error) {
	if cfg.Date != "" {
		if err := client.ReleaseExists(ctx, *cfg.sourceRepo, cfg.Date); err != nil {
			return "", fmt.Errorf("release %s not found: %w", cfg.Date, err)
		}
		return cfg.Date, nil
	}

	opts := github.ReleasesOptions{
		// safe page size to be sure to get at least one release 'YYYY-MM-DD'
		PageSize:         50,
		ReturnFirstValue: true,
		SortOrder:        github.SortOrderDesc,
	}
	releases, err := client.GetReleases(ctx, *cfg.sourceRepo, opts)
	if err != nil {
		return "", fmt.Errorf("failed to fetch releases: %w", err)
	}
	if len(releases) == 0 {
		return "", fmt.Errorf("no releases found")
	}
	return releases[0].TagName, nil
}

// VerifyConfig configures the bundle verification.
type VerifyConfig struct {
	// Bundle is the content of the trusted bundle to verify.
	//
	// Required.
	Bundle []byte

	// BundleMetadata is the metadata of the bundle to verify.
	//
	// Optional. If not provided, the metadata will be extracted from the bundle content.
	BundleMetadata *bundle.Metadata

	// Checksum is the content of the checksums.txt file to use for verification.
	//
	// Optional. If not provided, the checksum file will be downloaded from the release
	// matching the bundle date.
	Checksum []byte

	// ChecksumSignature is the content of the checksums.txt.sigstore.json file to use for verification.
	//
	// Optional. If not provided, the checksum signature file will be downloaded from the release
	// matching the bundle date.
	ChecksumSignature []byte

	// HTTPClient is the HTTP client to use for requests.
	//
	// Optional. If nil, http.DefaultClient will be used.
	HTTPClient *http.Client

	// sourceRepo is the GitHub repository to fetch bundles from.
	//
	// This field is internal for security reasons and should not be set by users.
	sourceRepo *github.Repo
}

// CheckAndSetDefaults validates and sets default values.
func (c *VerifyConfig) CheckAndSetDefaults() error {
	if len(c.Bundle) == 0 {
		return fmt.Errorf("bundle cannot be empty")
	}

	if c.BundleMetadata == nil {
		metadata, err := bundle.ParseMetadata(c.Bundle)
		if err != nil {
			return fmt.Errorf("failed to parse bundle metadata: %w", err)
		}
		c.BundleMetadata = metadata
	}

	if c.sourceRepo == nil {
		c.sourceRepo = &github.Repo{
			Owner: github.SourceRepo.Owner,
			Name:  github.SourceRepo.Name,
		}
	}
	if err := c.sourceRepo.CheckAndSetDefaults(); err != nil {
		return fmt.Errorf("invalid source repository: %w", err)
	}
	if c.HTTPClient == nil {
		c.HTTPClient = HttpClient()
	}

	return nil
}

// VerifyTrustedBundle verifies the authenticity and integrity of a TPM trust bundle.
//
// The function performs cryptographic verification using both Cosign signatures
// and GitHub Attestations. It can optionally download missing verification artifacts
// (checksums and signatures) from GitHub releases.
//
// Example:
//
//	// Verify with auto-detected metadata and auto-downloaded checksums
//	err := rot.VerifyTrustedBundle(context.Background(), rot.VerifyConfig{
//	    Bundle: bundleData,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify with explicit metadata and checksums
//	err = rot.VerifyTrustedBundle(context.Background(), rot.VerifyConfig{
//	    Bundle:            bundleData,
//	    Date:              "2025-12-05",
//	    Commit:            "abc123...",
//	    Checksum:          checksumData,
//	    ChecksumSignature: checksumSigData,
//	})
func VerifyTrustedBundle(ctx context.Context, cfg VerifyConfig) (*VerifyResult, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	client := github.NewHTTPClient(cfg.HTTPClient)

	effectiveChecksum := cfg.Checksum
	effectiveChecksumSig := cfg.ChecksumSignature

	assetCfg := assetConfig{
		client: client,
		repo:   *cfg.sourceRepo,
		date:   cfg.BundleMetadata.Date,
	}
	if len(effectiveChecksum) == 0 {
		var err error
		assetCfg.name = checksumsFile
		effectiveChecksum, err = getAsset(ctx, assetCfg)
		if err != nil {
			return nil, err
		}
	}
	if len(effectiveChecksumSig) == 0 {
		var err error
		assetCfg.name = checksumsSig
		effectiveChecksumSig, err = getAsset(ctx, assetCfg)
		if err != nil {
			return nil, err
		}
	}

	verifierCfg := verifier.Config{
		Date:             cfg.BundleMetadata.Date,
		Commit:           cfg.BundleMetadata.Commit,
		SourceRepo:       cfg.sourceRepo,
		WorkflowFilename: github.ReleaseBundleWorkflowPath,
		GitHubClient:     client,
	}

	v, err := verifier.New(verifierCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	bundleDigest := digest.ComputeSHA256(cfg.Bundle)
	result, err := v.Verify(ctx, cfg.Bundle, effectiveChecksum, effectiveChecksumSig, bundleDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundleVerificationFailed, err)
	}

	return result, nil
}

type assetConfig struct {
	client *github.HTTPClient
	repo   github.Repo
	name   string
	date   string
}

func getAsset(ctx context.Context, cfg assetConfig) ([]byte, error) {
	asset, err := cfg.client.DownloadAsset(ctx, cfg.repo, cfg.date, cfg.name)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s: %w", cfg.name, err)
	}
	return asset, nil
}
