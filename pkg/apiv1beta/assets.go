package apiv1beta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/observability"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"golang.org/x/sync/errgroup"
)

var (
	ErrIncompleteCache = fmt.Errorf("incomplete cache: missing verification assets")
)

// assetsConfig configures which assets to download.
type assetsConfig struct {
	bundle                []byte
	httpClient            utils.HTTPClient
	sourceRepo            *github.Repo
	cachePath             string
	disableLocalCache     bool
	tag                   string
	needChecksums         bool
	needChecksumSignature bool
	needProvenance        bool
}

func (c *assetsConfig) CheckAndSetDefaults() error {
	if c.tag == "" {
		return fmt.Errorf("tag cannot be empty")
	}
	if c.httpClient == nil {
		c.httpClient = HTTPClient()
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
	return c.needChecksums || c.needChecksumSignature || c.needProvenance
}

type assets struct {
	rootBundleData         []byte
	intermediateBundleData []byte
	checksum               []byte
	checksumSignature      []byte
	provenance             []byte
}

func getAssets(ctx context.Context, cfg assetsConfig) (*assets, error) {
	ctx, span := observability.StartSpan(ctx, "tpmtb.getAssets")
	defer span.End()

	if err := cfg.CheckAndSetDefaults(); err != nil {
		observability.RecordError(span, err)
		return nil, fmt.Errorf("invalid assets config: %w", err)
	}

	var (
		assets *assets
		err    error
	)
	if !cfg.disableLocalCache {
		if checkCacheExists(cfg.cachePath, cfg.tag) {
			assets, err = getAssetsFromCache(ctx, cfg)
			// Ignore ErrIncompleteCache to fallback to GitHub
			if err != nil && !errors.Is(err, ErrIncompleteCache) {
				observability.RecordError(span, err)
				return nil, fmt.Errorf("failed to load from cache: %w", err)
			}
		}
	}

	if assets == nil {
		assets, err = getAssetsFromGitHub(ctx, cfg)
		if err != nil {
			observability.RecordError(span, err)
			return nil, err
		}
	}

	return assets, nil
}

// getAssetsFromCache retrieves a TPM trust bundle and its verification assets from local cache.
func getAssetsFromCache(ctx context.Context, cfg assetsConfig) (*assets, error) {
	_, span := observability.StartSpan(ctx, "tpmtb.getAssetsFromCache")
	defer span.End()

	rootBundleData, err := cache.LoadFile(cfg.cachePath, cache.RootBundleFilename)
	if err != nil {
		observability.RecordError(span, err)
		return nil, err
	}
	intermediateBundleData, err := cache.LoadFile(cfg.cachePath, cache.IntermediateBundleFilename)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		observability.RecordError(span, err)
		return nil, err
	}

	result := &assets{
		rootBundleData:         rootBundleData,
		intermediateBundleData: intermediateBundleData,
	}

	if !cfg.shouldFetchVerificationAssets() {
		return result, nil
	}
	c, err := getCacheConfig(cfg.cachePath)
	if err != nil {
		observability.RecordError(span, err)
		return nil, err
	}
	if c.SkipVerify && cfg.shouldFetchVerificationAssets() {
		observability.RecordError(span, ErrIncompleteCache)
		return nil, ErrIncompleteCache
	}

	checksum, err := cache.LoadFile(cfg.cachePath, cache.ChecksumsFilename)
	if err != nil {
		observability.RecordError(span, err)
		return nil, err
	}

	checksumSig, err := cache.LoadFile(cfg.cachePath, cache.ChecksumsSigFilename)
	if err != nil {
		observability.RecordError(span, err)
		return nil, err
	}

	provenance, err := cache.LoadFile(cfg.cachePath, cache.ProvenanceFilename)
	if err != nil {
		observability.RecordError(span, err)
		return nil, err
	}

	if len(provenance) == 0 ||
		len(checksum) == 0 ||
		len(checksumSig) == 0 {
		observability.RecordError(span, ErrIncompleteCache)
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
	ctx, span := observability.StartSpan(ctx, "tpmtb.getAssetsFromGitHub")
	defer span.End()

	client := github.NewHTTPClient(cfg.httpClient)
	response := &assets{}

	// Step 1: Download checksums.txt to determine which bundles to fetch
	var (
		checksum    []byte
		checksumErr error
	)
	func() {
		ctx, span := observability.StartSpan(ctx, "tpmtb.downloadChecksums")
		defer span.End()
		checksum, checksumErr = client.DownloadReleaseAsset(ctx, *cfg.sourceRepo, cfg.tag, checksumsFile)
		if checksumErr != nil {
			observability.RecordError(span, checksumErr)
		}
	}()
	if checksumErr != nil {
		observability.RecordError(span, checksumErr)
		return nil, fmt.Errorf("failed to download checksums: %w", checksumErr)
	}
	if cfg.needChecksums {
		response.checksum = checksum
	}

	// Steps 2: Download checksum signature
	if cfg.needChecksumSignature {
		ctx, span := observability.StartSpan(ctx, "tpmtb.downloadChecksumSignature")
		defer span.End()
		sig, err := client.DownloadReleaseAsset(ctx, *cfg.sourceRepo, cfg.tag, checksumsSig)
		if err != nil {
			observability.RecordError(span, err)
			return nil, fmt.Errorf("failed to download checksum signature: %w", err)
		}
		response.checksumSignature = sig
	}

	// Step 3: Handle provided bundle
	providedBundleType, err := handleProvidedBundle(cfg.bundle, response)
	if err != nil {
		return nil, err
	}

	// Step 4: Download bundles not provided in config (parallelized internally)
	if err := downloadMissingBundles(ctx, client, cfg, checksum, providedBundleType, response); err != nil {
		observability.RecordError(span, err)
		return nil, err
	}

	// Step 5: Download provenance if needed
	if cfg.needProvenance {
		provenanceCtx, provenanceSpan := observability.StartSpan(ctx, "tpmtb.downloadProvenance")
		var provenanceErr error
		response.provenance, provenanceErr = downloadProvenance(provenanceCtx, client, cfg, response.rootBundleData)
		if provenanceErr != nil {
			observability.RecordError(provenanceSpan, provenanceErr)
			provenanceSpan.End()
			observability.RecordError(span, provenanceErr)
			return nil, provenanceErr
		}
		provenanceSpan.End()
	}

	return response, nil
}

// handleProvidedBundle processes a bundle provided via config and assigns it to the response.
func handleProvidedBundle(bundleData []byte, response *assets) (bundle.BundleType, error) {
	if len(bundleData) == 0 {
		return bundle.TypeUnspecified, nil
	}

	metadata, err := bundle.ParseMetadata(bundleData)
	if err != nil {
		return bundle.TypeUnspecified, fmt.Errorf("failed to parse bundle metadata: %w", err)
	}

	switch metadata.Type {
	case bundle.TypeRoot:
		response.rootBundleData = bytes.Clone(bundleData)
	case bundle.TypeIntermediate:
		response.intermediateBundleData = bytes.Clone(bundleData)
	default:
		return bundle.TypeUnspecified, fmt.Errorf("unsupported bundle type: %s", metadata.Type)
	}

	return metadata.Type, nil
}

// downloadMissingBundles downloads bundles that weren't provided in config.
// Downloads are performed in parallel when both bundles need to be fetched.
func downloadMissingBundles(ctx context.Context, client *github.HTTPClient, cfg assetsConfig, checksum []byte, providedType bundle.BundleType, response *assets) error {
	var (
		rootData         []byte
		intermediateData []byte
	)

	g, gctx := errgroup.WithContext(ctx)

	if providedType != bundle.TypeRoot && hasBundle(checksum, bundle.TypeRoot) {
		g.Go(func() error {
			ctx, span := observability.StartSpan(gctx, "tpmtb.downloadRootBundle")
			defer span.End()
			data, err := client.DownloadReleaseAsset(ctx, *cfg.sourceRepo, cfg.tag, bundleFilename)
			if err != nil {
				observability.RecordError(span, err)
				return fmt.Errorf("failed to download bundle: %w", err)
			}
			rootData = data
			return nil
		})
	}

	if providedType != bundle.TypeIntermediate && hasBundle(checksum, bundle.TypeIntermediate) {
		g.Go(func() error {
			ctx, span := observability.StartSpan(gctx, "tpmtb.downloadIntermediateBundle")
			defer span.End()
			data, err := client.DownloadReleaseAsset(ctx, *cfg.sourceRepo, cfg.tag, intermediateBundleFilename)
			if err != nil {
				observability.RecordError(span, err)
				return fmt.Errorf("failed to download intermediate bundle: %w", err)
			}
			intermediateData = data
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}

	if rootData != nil {
		response.rootBundleData = rootData
	}
	if intermediateData != nil {
		response.intermediateBundleData = intermediateData
	}

	return nil
}

// downloadProvenance downloads and returns the provenance attestation for the given bundle.
func downloadProvenance(ctx context.Context, client *github.HTTPClient, cfg assetsConfig, rootBundleData []byte) ([]byte, error) {
	if len(rootBundleData) == 0 {
		return nil, fmt.Errorf("root bundle data is required for provenance verification")
	}

	bundleDigest := digest.ComputeSHA256(rootBundleData)
	attestations, err := client.GetAttestations(ctx, *cfg.sourceRepo, bundleDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestations: %w", err)
	}
	if len(attestations) == 0 {
		return nil, fmt.Errorf("no attestations found for digest %s", bundleDigest)
	}

	provenanceJSON, err := json.Marshal(attestations[0].Bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal provenance: %w", err)
	}

	compactJSON, _ := utils.JsonCompact(provenanceJSON) // should never fail
	return compactJSON, nil
}

// hasBundle checks if the checksums.txt file contains an entry for the specified bundle type.
func hasBundle(checksumData []byte, bundleType bundle.BundleType) bool {
	filename := bundleFilename // default to root bundle filename
	if bundleType == bundle.TypeIntermediate {
		filename = intermediateBundleFilename
	}
	return bytes.Contains(checksumData, []byte(filename))
}

// getReleaseTag determines which release to fetch.
func getReleaseTag(ctx context.Context, cfg GetConfig) (string, error) {
	ctx, span := observability.StartSpan(ctx, "tpmtb.getReleaseTag")
	defer span.End()

	client := github.NewHTTPClient(cfg.HTTPClient)
	if cfg.Date != "" {
		if err := client.ReleaseExists(ctx, *cfg.sourceRepo, cfg.Date); err != nil {
			observability.RecordError(span, err)
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
		observability.RecordError(span, err)
		return "", fmt.Errorf("failed to fetch releases: %w", err)
	}
	if len(releases) == 0 {
		err := fmt.Errorf("no releases found")
		observability.RecordError(span, err)
		return "", err
	}

	return releases[0].TagName, nil
}
