package download

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle/verifier"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	"github.com/loicsikidi/tpm-ca-certificates/internal/transparency/utils/digest"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"github.com/spf13/cobra"
)

const (
	bundleFilename = "tpm-ca-certificates.pem"
	checksumsFile  = "checksums.txt"
	checksumsSig   = "checksums.txt.sigstore.json"
)

var (
	skipVerify bool
	force      bool
	date       string
	outputDir  string
)

// NewCommand creates the download command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "download",
		Short: "download a TPM trust bundle from GitHub releases and verify it",
		Long: `Download a TPM trust bundle from GitHub releases and optionally verify it.

The download command fetches a bundle from GitHub releases and can automatically
verify its authenticity using the same verification process as the verify command.`,
		Example: `  # Download the latest bundle to current directory
  tpmtb bundle download

  # Download a specific bundle by date
  tpmtb bundle download --date 2025-12-03

  # Download without verification
  tpmtb bundle download --skip-verify

  # Download and overwrite existing file without prompting
  tpmtb bundle download --force

  # Download to a specific directory
  tpmtb bundle download --output-dir /tmp`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE:         run,
	}

	cmd.Flags().BoolVar(&skipVerify, "skip-verify", false,
		"Skip bundle verification after download")
	cmd.Flags().BoolVarP(&force, "force", "f", false,
		"Overwrite existing files without prompting")
	cmd.Flags().StringVarP(&date, "date", "d", "",
		"Bundle release date (YYYY-MM-DD), default: latest")
	cmd.Flags().StringVarP(&outputDir, "output-dir", "o", ".",
		"Output directory for downloaded files")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	client := github.NewHTTPClient(nil)

	releaseTag := date
	if releaseTag == "" {
		fmt.Println("Fetching latest release...")
		opts := github.ReleasesOptions{
			PageSize:         50, // to be safe if many versioned releases exist in comparison to bundle releases
			ReturnFirstValue: true,
			SortOrder:        github.SortOrderDesc,
		}
		releases, err := client.GetReleases(cmd.Context(), github.SourceRepo, opts)
		if err != nil {
			return fmt.Errorf("failed to fetch releases: %w", err)
		}
		if len(releases) == 0 {
			return fmt.Errorf("no releases found")
		}
		releaseTag = releases[0].TagName
		fmt.Printf("Latest release: %s\n", releaseTag)
	} else {
		// If date is specified, verify the release exists
		fmt.Printf("Checking if release %s exists...\n", releaseTag)
		if err := client.ReleaseExists(cmd.Context(), github.SourceRepo, releaseTag); err != nil {
			return err
		}
	}

	if !utils.DirExists(outputDir) {
		return fmt.Errorf("output directory %s does not exist", outputDir)
	}

	bundlePath := filepath.Join(outputDir, bundleFilename)
	checksumsPath := filepath.Join(outputDir, checksumsFile)
	checksumsSigPath := filepath.Join(outputDir, checksumsSig)

	if utils.FileExists(bundlePath) && !force {
		cli.DisplayWarning("File %s already exists.", bundlePath)
		if !cli.PromptConfirmation("Override?") {
			fmt.Println() // Add newline for clean output after prompt
			return fmt.Errorf("download cancelled")
		}
		fmt.Println() // Add newline for clean output after prompt
	}

	fmt.Printf("Downloading %s from release %s...\n\n", bundleFilename, releaseTag)
	if err := client.DownloadAsset(cmd.Context(), github.SourceRepo, releaseTag, bundleFilename, bundlePath); err != nil {
		return fmt.Errorf("failed to download bundle: %w", err)
	}
	cli.DisplaySuccess("✅ Downloaded bundle to %s", bundlePath)

	if skipVerify {
		cli.DisplayWarning("⚠️  Verification skipped (--skip-verify)")
		return nil
	}

	// Setup cleanup for verification files
	// Track verification success to decide what to cleanup
	var verificationSucceeded bool
	defer func() {
		if verificationSucceeded {
			if err := cleanupFiles(checksumsPath, checksumsSigPath); err != nil {
				cli.DisplayWarning("⚠️  Warning: failed to cleanup checksum files: %v", err)
			}
		} else {
			// Cleanup everything on failure we might expect errors
			// because some files might not exist if failure happened early
			// so we ignore errors on purpose here
			cleanupFiles(bundlePath, checksumsPath, checksumsSigPath) //nolint:errcheck
		}
	}()

	fmt.Println("Downloading checksum files...")
	if err := client.DownloadAsset(cmd.Context(), github.SourceRepo, releaseTag, checksumsFile, checksumsPath); err != nil {
		return fmt.Errorf("failed to download checksums: %w", err)
	}
	if err := client.DownloadAsset(cmd.Context(), github.SourceRepo, releaseTag, checksumsSig, checksumsSigPath); err != nil {
		return fmt.Errorf("failed to download checksums signature: %w", err)
	}

	metadata, err := bundle.ParseMetadata(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to parse bundle metadata: %w", err)
	}

	bundleDigest, err := digest.ComputeSHA256(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to compute digest: %w", err)
	}

	fmt.Println("Verifying bundle...")
	fmt.Println()

	cfg := verifier.Config{
		BundlePath:         bundlePath,
		Date:               metadata.Date,
		Commit:             metadata.Commit,
		ChecksumsFile:      checksumsPath,
		ChecksumsSignature: checksumsSigPath,
		SourceRepo:         &github.SourceRepo,
		WorkflowFilename:   github.ReleaseBundleWorkflowPath,
	}

	v, err := verifier.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	_, err = v.Verify(cmd.Context(), bundleDigest)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	verificationSucceeded = true

	cli.DisplaySuccess("✅ Bundle downloaded and verified: %s", bundlePath)
	return nil
}

// cleanupFiles removes the specified files, ignoring errors.
func cleanupFiles(paths ...string) error {
	var firstErr error
	for _, path := range paths {
		if err := os.Remove(path); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
