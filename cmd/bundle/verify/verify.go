package verify

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/cosign"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
	"github.com/spf13/cobra"
)

// Opts represents the configuration options for the verify command.
type Opts struct {
	ChecksumsFile      string
	ChecksumsSignature string
	CacheDir           string
	Offline            bool
}

// NewCommand creates the verify command.
//
// The verify command validates the authenticity and integrity of a TPM trust bundle
// using GitHub Attestations and optionally Cosign signatures.
func NewCommand() *cobra.Command {
	o := &Opts{}

	cmd := &cobra.Command{
		Use:   "verify <bundle-file>",
		Short: "verify the authenticity and integrity of a TPM trust bundle",
		Long: `Verify a TPM trust bundle using Sigstore/Cosign and GitHub Attestations.

The verify command performs two types of verification (both required):

1. Cosign Signature Verification (Phase 1):
   - Retrieve smartly checksums.txt and checksums.txt.sigstore.json (if not given)
   - Verifies signature bundle format using Sigstore
   - Validates checksum matches the bundle

2. GitHub Attestation Verification (Phase 2):
   - Fetches attestations from GitHub API
   - Verifies SLSA provenance using Sigstore
   - Validates certificate identity (OIDC issuer, source repository)

Both verifications must succeed for the bundle to be considered valid.`,
		Example: `  # Verify bundle with default settings
  tpmtb bundle verify tpm-ca-certificates.pem

  # Verify with explicit checksum files
  tpmtb bundle verify tpm-ca-certificates.pem --checksums-file checksums.txt --checksums-signature checksums.txt.sigstore.json

  # Verify bundle from stdin
  cat tpm-ca-certificates.pem | tpmtb bundle verify -

  # Verify bundle in offline mode using default cache directory
  tpmtb bundle verify tpm-ca-certificates.pem --offline

  # Verify bundle in offline mode with custom cache directory
  tpmtb bundle verify tpm-ca-certificates.pem --offline --cache-dir /path/to/cache`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, o)
		},
	}

	cmd.Flags().StringVar(&o.ChecksumsFile, "checksums-file", "",
		"Path to checksums.txt file (optional, default: auto-detect or download)")
	cmd.Flags().StringVar(&o.ChecksumsSignature, "checksums-signature", "",
		"Path to checksums.txt.sigstore.json file (optional, default: auto-detect or download)")
	cmd.Flags().StringVarP(&o.CacheDir, "cache-dir", "c", "",
		"Cache directory path (optional, default: $HOME/.tpmtb)")
	cmd.Flags().BoolVarP(&o.Offline, "offline", "o", false,
		"Enable offline verification mode using cached assets")
	return cmd
}

func run(cmd *cobra.Command, args []string, o *Opts) error {
	bundlePath := args[0]

	if o.CacheDir != "" && !utils.DirExists(o.CacheDir) {
		return fmt.Errorf("cache directory does not exist: %s", o.CacheDir)
	}

	var bundleDir, bundleFilename string
	if bundlePath == "-" {
		var err error
		bundleDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current working directory: %w", err)
		}
		bundleFilename = "stdin"
	} else {
		bundleDir = filepath.Dir(bundlePath)
		bundleFilename = filepath.Base(bundlePath)
	}

	bundleData, err := utils.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to read bundle file: %w", err)
	}

	metadata, err := bundle.ParseMetadata(bundleData)
	if err != nil {
		return fmt.Errorf("failed to parse bundle metadata: %w", err)
	}

	cfg := apiv1beta.VerifyConfig{
		Bundle:         bundleData,
		BundleMetadata: metadata,
	}

	displayBundleMetadata(metadata)

	displayDigest(digest.ComputeSHA256(bundleData), bundleFilename)

	// Enrich config with CLI options
	if err := enrichConfig(&cfg, *o, bundleDir); err != nil {
		return err
	}

	fmt.Println()
	displayTitle("Verification in progress...")
	fmt.Println()

	result, err := apiv1beta.VerifyTrustedBundle(cmd.Context(), cfg)
	if err != nil {
		if errors.Is(err, apiv1beta.ErrBundleVerificationFailed) {
			cli.DisplayError("❌ Verification failed")
		} else {
			cli.DisplayError("An error occurred during verification")
		}
		return err
	}

	displaySuccess(result, metadata)

	return nil
}

type checksumsData struct {
	checksumData    []byte
	checksumSigData []byte
}

func readChecksumsData(checksumsFile, checksumsSignature string) (*checksumsData, error) {
	var data checksumsData
	var err error

	if checksumsFile != "" {
		data.checksumData, err = utils.ReadFile(checksumsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read checksums file: %w", err)
		}
	}

	if checksumsSignature != "" {
		data.checksumSigData, err = utils.ReadFile(checksumsSignature)
		if err != nil {
			return nil, fmt.Errorf("failed to read checksums signature file: %w", err)
		}
	}
	return &data, nil
}

func enrichConfig(cfg *apiv1beta.VerifyConfig, o Opts, bundleDir string) error {
	// In offline mode, load all verification assets from cache
	if o.Offline {
		cacheDir := o.CacheDir
		if cacheDir == "" {
			cacheDir = cache.CacheDir()
		}
		if err := cache.ValidateCacheFiles(cacheDir); err != nil {
			return fmt.Errorf("offline mode requires all cache files to be present: %w", err)
		}

		trustedRootData, err := cache.LoadFile(cacheDir, cache.TrustedRootFilename)
		if err != nil {
			return err
		}
		cfg.TrustedRoot = trustedRootData

		checksumData, err := cache.LoadFile(cacheDir, cache.ChecksumsFilename)
		if err != nil {
			return err
		}
		cfg.Checksum = checksumData

		checksumSigData, err := cache.LoadFile(cacheDir, cache.ChecksumsSigFilename)
		if err != nil {
			return err
		}
		cfg.ChecksumSignature = checksumSigData

		provenanceData, err := cache.LoadFile(cacheDir, cache.ProvenanceFilename)
		if err != nil {
			return err
		}
		cfg.Provenance = provenanceData
	} else {
		// Online mode: try to auto-detect or download checksum files
		skipReadFiles := false
		if o.ChecksumsFile == "" && o.ChecksumsSignature == "" {
			fmt.Println("Auto-detecting checksum files...")
			checksumPath, checksumSigPath, found := cosign.FindChecksumFiles(bundleDir)
			if !found {
				fmt.Println("Checksum files not found locally, will be downloaded from GitHub...")
				skipReadFiles = true
			}
			o.ChecksumsFile, o.ChecksumsSignature = checksumPath, checksumSigPath
		}
		if !skipReadFiles {
			result, err := readChecksumsData(o.ChecksumsFile, o.ChecksumsSignature)
			if err != nil {
				return err
			}
			cfg.Checksum = result.checksumData
			cfg.ChecksumSignature = result.checksumSigData
		}
	}
	return nil
}
