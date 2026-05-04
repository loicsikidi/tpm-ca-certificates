package apiv1beta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/observability"
	verifierutils "github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

type VerifyResult = verifier.VerifyResult

var (
	mu         sync.RWMutex
	httpClient = http.DefaultClient // default HTTP client
)

const (
	bundleFilename             = cache.RootBundleFilename
	intermediateBundleFilename = cache.IntermediateBundleFilename
	checksumsFile              = cache.ChecksumsFilename
	checksumsSig               = cache.ChecksumsSigFilename
)

var (
	// ErrBundleNotFound is returned when the requested bundle is not found.
	ErrBundleNotFound = errors.New("trusted bundle not found for the specified date")

	// ErrBundleVerificationFailed is returned when the bundle verification fails.
	ErrBundleVerificationFailed = errors.New("trusted bundle verification failed")

	// ErrCannotPersistTrustedBundle is returned when the bundle cannot be persisted due to disabled local cache.
	ErrCannotPersistTrustedBundle = errors.New("local cache is disabled; cannot persist bundle")
)

// HTTPClient returns the current HTTP client used for requests.
func HTTPClient() *http.Client {
	mu.RLock()
	defer mu.RUnlock()
	return httpClient
}

// SetHTTPClient sets a custom HTTP client for requests.
func SetHTTPClient(client *http.Client) {
	mu.Lock()
	defer mu.Unlock()
	httpClient = client
}

// GetTrustedBundle retrieves and parses a TPM trust bundle from GitHub releases.
//
// The function downloads the bundle, verifies it (unless SkipVerify is true),
// parses it into a certificate catalog organized by vendor, and returns a [TrustedBundle]
// interface that provides thread-safe access to the bundle data.
//
// If AutoUpdate is enabled, the bundle will automatically check for updates in the background
// and update itself when a newer version is available.
//
// Example:
//
//	// Get the latest verified bundle with all certificates
//	tb, err := apiv1beta.GetTrustedBundle(context.Background(), apiv1beta.GetConfig{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer tb.Stop()
//
//	certPool := tb.GetRoots()
//
//	// Get a specific date's bundle filtered by vendor
//	tb, err = apiv1beta.GetTrustedBundle(context.Background(), apiv1beta.GetConfig{
//	    Date:      "2025-12-03",
//	    VendorIDs: []apiv1beta.VendorID{apiv1beta.IFX, apiv1beta.NTC},
//	})
//
//	// Enable auto-update every 6 hours
//	tb, err = apiv1beta.GetTrustedBundle(context.Background(), apiv1beta.GetConfig{
//	    AutoUpdate: apiv1beta.AutoUpdateConfig{
//	        Interval: 6 * time.Hour,
//	    },
//	})
func GetTrustedBundle(ctx context.Context, cfg GetConfig) (TrustedBundle, error) {
	ctx, span := observability.StartSpan(ctx, "tpmtb.GetTrustedBundle")
	defer span.End()

	if err := cfg.CheckAndSetDefaults(); err != nil {
		observability.RecordError(span, err)
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	releaseTag, err := getReleaseTag(ctx, cfg)
	if err != nil {
		observability.RecordError(span, err)
		return nil, err
	}

	assetsCfg := cfg.toAssetsConfig()
	assetsCfg.tag = releaseTag
	assets, err := getAssets(ctx, assetsCfg)
	if err != nil {
		observability.RecordError(span, err)
		return nil, err
	}

	if !cfg.SkipVerify {
		// Verify root bundle
		if _, err := VerifyTrustedBundle(ctx, VerifyConfig{
			Bundle:            assets.rootBundleData,
			Checksum:          assets.checksum,
			ChecksumSignature: assets.checksumSignature,
			Provenance:        assets.provenance,
			sourceRepo:        cfg.sourceRepo,
			HTTPClient:        cfg.HTTPClient,
			DisableLocalCache: cfg.DisableLocalCache,
		}); err != nil {
			observability.RecordError(span, err)
			return nil, fmt.Errorf("root bundle verification failed: %w", err)
		}

		// Verify intermediate bundle if present
		if len(assets.intermediateBundleData) > 0 {
			if _, err := VerifyTrustedBundle(ctx, VerifyConfig{
				Bundle:            assets.intermediateBundleData,
				Checksum:          assets.checksum,
				ChecksumSignature: assets.checksumSignature,
				Provenance:        assets.provenance,
				sourceRepo:        cfg.sourceRepo,
				HTTPClient:        cfg.HTTPClient,
				DisableLocalCache: cfg.DisableLocalCache,
			}); err != nil {
				observability.RecordError(span, err)
				return nil, fmt.Errorf("intermediate bundle verification failed: %w", err)
			}
		}
	}

	tb, err := newTrustedBundle(ctx, assets.rootBundleData, assets.intermediateBundleData)
	if err != nil {
		observability.RecordError(span, err)
		return nil, err
	}

	// Cache additional config to the trusted bundle
	tbImpl := tb.(*trustedBundle)
	tbImpl.disableLocalCache = cfg.DisableLocalCache
	tbImpl.vendorFilter = cfg.VendorIDs
	tbImpl.autoUpdateCfg = &cfg.AutoUpdate
	tbImpl.assets = assets

	// Parse intermediate bundle metadata if present
	if len(assets.intermediateBundleData) > 0 {
		intermediateMetadata, err := bundle.ParseMetadata(assets.intermediateBundleData)
		if err != nil {
			observability.RecordError(span, err)
			return nil, fmt.Errorf("failed to parse intermediate bundle metadata: %w", err)
		}
		tbImpl.intermediateMetadata = intermediateMetadata
	}

	if !cfg.DisableLocalCache {
		// Persist only if not already cached
		if !checkCacheExists(cfg.CachePath, releaseTag) {
			if err := tbImpl.Persist(ctx, cfg.CachePath); err != nil {
				observability.RecordError(span, err)
				return nil, fmt.Errorf("failed to persist bundle to cache (if running on read-only filesystem, set DisableLocalCache=true): %w", err)
			}
		}
	}

	if !cfg.AutoUpdate.DisableAutoUpdate {
		tbImpl.startWatcher(ctx, cfg, cfg.AutoUpdate.Interval)
	}

	return tb, nil
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
//	err := apiv1beta.VerifyTrustedBundle(context.Background(), apiv1beta.VerifyConfig{
//	    Bundle: bundleData,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify with explicit metadata and checksums
//	err = apiv1beta.VerifyTrustedBundle(context.Background(), apiv1beta.VerifyConfig{
//	    Bundle:            bundleData,
//	    BundleMetadata:    &bundle.Metadata{Date: "2025-12-05", Commit: "abc123"},
//	    Checksum:          checksumData,
//	    ChecksumSignature: checksumSigData,
//	})
func VerifyTrustedBundle(ctx context.Context, cfg VerifyConfig) (*VerifyResult, error) {
	ctx, span := observability.StartSpan(ctx, "tpmtb.VerifyTrustedBundle")
	defer span.End()

	if err := cfg.CheckAndSetDefaults(); err != nil {
		observability.RecordError(span, err)
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if cfg.shouldFetchVerificationAssets() {
		assets, err := getAssets(ctx, cfg.toAssetsConfig())
		if err != nil {
			observability.RecordError(span, err)
			return nil, fmt.Errorf("failed to download verification assets: %w", err)
		}
		if len(cfg.Checksum) == 0 {
			cfg.Checksum = assets.checksum
		}
		if len(cfg.ChecksumSignature) == 0 {
			cfg.ChecksumSignature = assets.checksumSignature
		}
		if len(cfg.Provenance) == 0 {
			cfg.Provenance = assets.provenance
		}
	}

	verifierCfg := verifier.Config{
		Date:              cfg.BundleMetadata.Date,
		Commit:            cfg.BundleMetadata.Commit,
		SourceRepo:        cfg.sourceRepo,
		WorkflowFilename:  github.ReleaseBundleWorkflowPath,
		HTTPClient:        cfg.HTTPClient,
		DisableLocalCache: cfg.DisableLocalCache,
		TrustedRoot:       cfg.TrustedRoot,
	}

	v, err := verifier.New(verifierCfg)
	if err != nil {
		observability.RecordError(span, err)
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	verifyCfg := verifier.VerifyConfig{
		BundleData:       cfg.Bundle,
		ChecksumsData:    cfg.Checksum,
		ChecksumsSigData: cfg.ChecksumSignature,
		ProvenanceData:   cfg.Provenance,
	}

	result, err := v.Verify(ctx, verifyCfg)
	if err != nil {
		observability.RecordError(span, err)
		return nil, fmt.Errorf("%w: %v", ErrBundleVerificationFailed, err)
	}

	return result, nil
}

// SaveResponse contains all assets required for offline verification of a TPM bundle.
type SaveResponse struct {
	// RootBundle is the TPM root CA certificates bundle (PEM format).
	RootBundle []byte

	// Provenance is the GitHub Attestation provenance for produced bundle.
	Provenance []byte

	// IntermediateBundle is the TPM intermediate CA certificates bundle (PEM format).
	//
	// This field will be empty if the release does not contain an intermediate bundle.
	IntermediateBundle []byte

	// Checksum is the checksums.txt file content.
	Checksum []byte

	// ChecksumSignature is the checksums.txt.sigstore.json file content.
	ChecksumSignature []byte

	// TrustedRoot is the Sigstore trusted_root.json from TUF.
	TrustedRoot []byte

	// CacheConfig is the cache configuration (JSON format) containing metadata about the bundle.
	CacheConfig []byte
}

// Persist writes all assets to the specified output directory.
//
// If outputDir is empty, the default cache directory ($HOME/.tpmtb) is used.
func (sr *SaveResponse) Persist(ctx context.Context, optionalOutputDir ...string) error {
	outputDir := utils.OptionalArgWithDefault(optionalOutputDir, cache.CacheDir())
	cleanOutputDir := filepath.Clean(outputDir)

	if !utils.DirExists(cleanOutputDir) {
		if err := os.MkdirAll(cleanOutputDir, 0700); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	return persistAllBundleAssets(
		cleanOutputDir,
		sr.RootBundle,
		sr.IntermediateBundle,
		sr.Checksum,
		sr.ChecksumSignature,
		sr.Provenance,
		sr.TrustedRoot,
		sr.CacheConfig,
	)
}

// SaveTrustedBundle retrieves a TPM trust bundle and all verification assets required for offline verification.
//
// This function downloads the bundle, verifies it, fetches the TUF trust chains from Rekor,
// and returns a [SaveResponse] containing all necessary files for offline verification.
//
// The returned [SaveResponse] can be persisted to disk using the Persist method, which will
// save all assets to the local cache directory ($HOME/.tpmtb by default).
//
// Example:
//
//	// Save the latest bundle with all verification assets
//	resp, err := apiv1beta.SaveTrustedBundle(context.Background(), apiv1beta.SaveConfig{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Persist to default cache directory ($HOME/.tpmtb)
//	if err := resp.Persist(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Save a specific date's bundle filtered by vendor
//	resp, err = apiv1beta.SaveTrustedBundle(context.Background(), apiv1beta.SaveConfig{
//	    Date:      "2025-12-05",
//	    VendorIDs: []apiv1beta.VendorID{apiv1beta.IFX, apiv1beta.NTC},
//	})
func SaveTrustedBundle(ctx context.Context, cfg SaveConfig) (*SaveResponse, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Use GetTrustedBundle to fetch and verify the bundle
	// This gives us all the assets and handles verification automatically
	tb, err := GetTrustedBundle(ctx, GetConfig{
		Date:       cfg.Date,
		CachePath:  cfg.CachePath,
		VendorIDs:  cfg.VendorIDs,
		HTTPClient: cfg.HTTPClient,
		AutoUpdate: AutoUpdateConfig{
			DisableAutoUpdate: true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get trusted bundle: %w", err)
	}

	// Fetch the Sigstore trusted_root.json from TUF
	trustedRoot, err := verifierutils.FetchTrustedRoot(cfg.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch trusted root: %w", err)
	}

	// Extract assets from the trusted bundle
	tbImpl := tb.(*trustedBundle)
	assets := tbImpl.assets
	metadata := tbImpl.rootMetadata

	// Build cache config
	cacheCfg := CacheConfig{
		Version:       metadata.Date,
		VendorIDs:     cfg.VendorIDs,
		AutoUpdate:    &AutoUpdateConfig{DisableAutoUpdate: true},
		SkipVerify:    false,
		LastTimestamp: time.Now(),
	}

	cacheConfigData, err := json.Marshal(cacheCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cache config: %w", err)
	}

	return &SaveResponse{
		RootBundle:         assets.rootBundleData,
		Provenance:         assets.provenance,
		IntermediateBundle: assets.intermediateBundleData,
		Checksum:           assets.checksum,
		ChecksumSignature:  assets.checksumSignature,
		TrustedRoot:        trustedRoot,
		CacheConfig:        cacheConfigData,
	}, nil
}
