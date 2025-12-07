package verify

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/cosign"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/api"
	"github.com/spf13/cobra"
)

var (
	checksumsFile      string
	checksumsSignature string
)

// NewCommand creates the verify command.
//
// The verify command validates the authenticity and integrity of a TPM trust bundle
// using GitHub Attestations and optionally Cosign signatures.
func NewCommand() *cobra.Command {
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
  tpmtb bundle verify tpm-ca-certificates.pem --checksums-file checksums.txt --checksums-signature checksums.txt.sigstore.json`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE:         run,
	}

	cmd.Flags().StringVar(&checksumsFile, "checksums-file", "",
		"Path to checksums.txt file (optional, default: auto-detect or download)")
	cmd.Flags().StringVar(&checksumsSignature, "checksums-signature", "",
		"Path to checksums.txt.sigstore.json file (optional, default: auto-detect or download)")
	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	bundlePath := args[0]
	bundleFilename := filepath.Base(bundlePath)

	// Read bundle from disk
	bundleData, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to read bundle file: %w", err)
	}

	metadata, err := bundle.ParseMetadata(bundleData)
	if err != nil {
		return fmt.Errorf("failed to parse bundle metadata: %w", err)
	}

	cfg := api.VerifyConfig{
		Bundle:         bundleData,
		BundleMetadata: metadata,
	}

	displayBundleMetadata(metadata)

	displayDigest(digest.ComputeSHA256(bundleData), bundleFilename)

	skipReadFiles := false
	if checksumsFile == "" && checksumsSignature == "" {
		fmt.Println("Auto-detecting checksum files...")
		checksumPath, checksumSigPath, found := cosign.FindChecksumFiles(bundlePath)
		if !found {
			fmt.Println("Checksum files not found locally, will be downloaded from GitHub...")
			skipReadFiles = true
		}
		checksumsFile, checksumsSignature = checksumPath, checksumSigPath
	}
	if !skipReadFiles {
		result, err := readChecksumsData(checksumsFile, checksumsSignature)
		if err != nil {
			return err
		}
		cfg.Checksum = result.checksumData
		cfg.ChecksumSignature = result.checksumSigData
	}

	fmt.Println()
	displayTitle("Verification in progress...")
	fmt.Println()

	result, err := api.VerifyTrustedBundle(cmd.Context(), cfg)
	if err != nil {
		if errors.Is(err, api.ErrBundleVerificationFailed) {
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
		data.checksumData, err = os.ReadFile(checksumsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read checksums file: %w", err)
		}
	}

	if checksumsSignature != "" {
		data.checksumSigData, err = os.ReadFile(checksumsSignature)
		if err != nil {
			return nil, fmt.Errorf("failed to read checksums signature file: %w", err)
		}
	}
	return &data, nil
}
