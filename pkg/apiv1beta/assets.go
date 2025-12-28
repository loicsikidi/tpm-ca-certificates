package apiv1beta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

var (
	ErrIncompleteCache = fmt.Errorf("incomplete cache: missing verification assets")
)

// assetsConfig configures which assets to download.
type assetsConfig struct {
	bundle                    []byte
	httpClient                utils.HttpClient
	sourceRepo                *github.Repo
	cachePath                 string
	disableLocalCache         bool
	tag                       string
	downloadChecksums         bool
	downloadChecksumSignature bool
	downloadProvenance        bool
}

func (c *assetsConfig) CheckAndSetDefaults() error {
	if c.tag == "" {
		return fmt.Errorf("tag cannot be empty")
	}
	if c.httpClient == nil {
		c.httpClient = HttpClient()
	}
	if c.cachePath == "" {
		c.cachePath = cache.CacheDir()
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
	return nil
}

func (c *assetsConfig) shouldFetchVerificationAssets() bool {
	return c.downloadChecksums || c.downloadChecksumSignature || c.downloadProvenance
}

type assets struct {
	rootBundleData         []byte
	intermediateBundleData []byte
	checksum               []byte
	checksumSignature      []byte
	provenance             []byte
}

func getAssets(ctx context.Context, cfg assetsConfig) (*assets, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid assets config: %w", err)
	}

	var (
		assets *assets
		err    error
	)
	if !cfg.disableLocalCache {
		if checkCacheExists(cfg.cachePath, cfg.tag) {
			assets, err = getAssetsFromCache(cfg)
			// Ignore ErrIncompleteCache to fallback to GitHub
			if err != nil && !errors.Is(err, ErrIncompleteCache) {
				return nil, fmt.Errorf("failed to load from cache: %w", err)
			}
		}
	}

	if assets == nil {
		assets, err = getAssetsFromGitHub(ctx, cfg)
		if err != nil {
			return nil, err
		}
	}
	return assets, nil
}

// getAssetsFromCache retrieves a TPM trust bundle and its verification assets from local cache.
func getAssetsFromCache(cfg assetsConfig) (*assets, error) {
	rootBundleData, err := cache.LoadFile(cache.RootBundleFilename, cfg.cachePath)
	if err != nil {
		return nil, err
	}
	intermediateBundleData, err := cache.LoadFile(cache.IntermediateBundleFilename, cfg.cachePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	result := &assets{
		rootBundleData:         rootBundleData,
		intermediateBundleData: intermediateBundleData,
	}

	if !cfg.shouldFetchVerificationAssets() {
		return result, nil
	}

	checksum, err := cache.LoadFile(cache.ChecksumsFilename, cfg.cachePath)
	if err != nil {
		return nil, err
	}

	checksumSig, err := cache.LoadFile(cache.ChecksumsSigFilename, cfg.cachePath)
	if err != nil {
		return nil, err
	}

	provenance, err := cache.LoadFile(cache.ProvenanceFilename, cfg.cachePath)
	if err != nil {
		return nil, err
	}

	if len(provenance) == 0 ||
		len(checksum) == 0 ||
		len(checksumSig) == 0 {
		return nil, ErrIncompleteCache
	}

	result.checksum = checksum
	result.checksumSignature = checksumSig
	result.provenance = provenance

	return result, nil
}

// getAssetsFromGitHub retrieves and optionally verifies a TPM trust bundle from GitHub.
//   - integrity: checksums.txt and checksums.txt.sigstore.json (stored in GitHub Releases)
//   - provenance: GitHub Attestation (stored in GitHub API)
func getAssetsFromGitHub(ctx context.Context, cfg assetsConfig) (*assets, error) {
	client := github.NewHTTPClient(cfg.httpClient)

	bundleData := bytes.Clone(cfg.bundle)
	if len(bundleData) == 0 {
		var err error
		bundleData, err = client.DownloadReleaseAsset(ctx, *cfg.sourceRepo, cfg.tag, bundleFilename)
		if err != nil {
			return nil, fmt.Errorf("failed to download bundle: %w", err)
		}
	}

	response := &assets{
		rootBundleData: bundleData,
	}

	if !cfg.shouldFetchVerificationAssets() {
		return response, nil
	}

	if cfg.downloadChecksums {
		checksum, err := client.DownloadReleaseAsset(ctx, *cfg.sourceRepo, cfg.tag, checksumsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to download checksums: %w", err)
		}
		response.checksum = checksum
	}

	if cfg.downloadChecksumSignature {
		checksumSig, err := client.DownloadReleaseAsset(ctx, *cfg.sourceRepo, cfg.tag, checksumsSig)
		if err != nil {
			return nil, fmt.Errorf("failed to download checksum signature: %w", err)
		}
		response.checksumSignature = checksumSig
	}

	// Download intermediate bundle if present in checksums.txt
	if len(response.checksum) > 0 && hasIntermediateBundle(response.checksum) {
		intermediateBundle, err := client.DownloadReleaseAsset(ctx, *cfg.sourceRepo, cfg.tag, intermediateBundleFilename)
		if err != nil {
			return nil, fmt.Errorf("failed to download intermediate bundle: %w", err)
		}
		response.intermediateBundleData = intermediateBundle
	}

	// Download provenance attestation if requested
	if cfg.downloadProvenance {
		bundleDigest := digest.ComputeSHA256(response.rootBundleData)
		attestations, err := client.GetAttestations(ctx, *cfg.sourceRepo, bundleDigest)
		if err != nil {
			return nil, fmt.Errorf("failed to get attestations: %w", err)
		}
		if len(attestations) == 0 {
			return nil, fmt.Errorf("no attestations found for digest %s", bundleDigest)
		}
		// Take the first attestation and serialize it to JSON
		provenanceJSON, err := json.Marshal(attestations[0].Bundle)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal provenance: %w", err)
		}
		compactJSON, _ := utils.JsonCompact(provenanceJSON) // should not fail
		response.provenance = compactJSON
	}

	return response, nil
}

// hasIntermediateBundle checks if the checksums.txt file contains an entry for the intermediate bundle.
func hasIntermediateBundle(checksumData []byte) bool {
	return bytes.Contains(checksumData, []byte(intermediateBundleFilename))
}

// getReleaseTag determines which release to fetch.
func getReleaseTag(ctx context.Context, cfg GetConfig) (string, error) {
	client := github.NewHTTPClient(cfg.HTTPClient)
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
