package download

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
	"github.com/spf13/cobra"
)

const (
	bundleFilename = "tpm-ca-certificates.pem"
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
	if !utils.DirExists(outputDir) {
		return fmt.Errorf("output directory %s does not exist", outputDir)
	}

	bundlePath := filepath.Join(outputDir, bundleFilename)

	if utils.FileExists(bundlePath) && !force {
		cli.DisplayWarning("File %s already exists.", bundlePath)
		if !cli.PromptConfirmation("Override?") {
			fmt.Println() // Add newline for clean output after prompt
			return fmt.Errorf("download cancelled")
		}
		fmt.Println() // Add newline for clean output after prompt
	}

	// Use the pkg/apiv1beta API to download and optionally verify the bundle
	if date == "" {
		fmt.Println("Fetching latest release...")
	} else {
		fmt.Printf("Fetching release %s...\n", date)
	}

	cfg := apiv1beta.GetConfig{
		Date:       date,
		SkipVerify: skipVerify,
	}

	trustedBundle, err := apiv1beta.GetTrustedBundle(cmd.Context(), cfg)
	if err != nil {
		if errors.Is(err, apiv1beta.ErrBundleVerificationFailed) {
			cli.DisplayError("❌ Bundle verification failed")
		}
		return err
	}

	if skipVerify {
		cli.DisplayWarning("⚠️ Verification skipped (--skip-verify)")
	} else {
		cli.DisplaySuccess("✅ Bundle verified")
	}

	if err := os.WriteFile(bundlePath, trustedBundle.GetRaw(), 0644); err != nil {
		return fmt.Errorf("failed to write bundle to disk: %w", err)
	}

	cli.DisplaySuccess("✅ Downloaded bundle to %s", bundlePath)

	return nil
}
