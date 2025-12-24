package download

import (
	"context"
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
	bundleFilename = apiv1beta.CacheRootBundleFilename
)

// Opts holds the configuration for the download command.
type Opts struct {
	SkipVerify bool
	Force      bool
	Date       string
	OutputDir  string
}

// NewCommand creates the download command.
func NewCommand() *cobra.Command {
	opts := &Opts{}

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
  tpmtb bundle download --output-dir /tmp

  # Print bundle to stdout
  tpmtb bundle download --output-dir -`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE:         func(cmd *cobra.Command, args []string) error { return Run(cmd.Context(), opts) },
	}

	cmd.Flags().BoolVar(&opts.SkipVerify, "skip-verify", false,
		"Skip bundle verification after download")
	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false,
		"Overwrite existing files without prompting")
	cmd.Flags().StringVarP(&opts.Date, "date", "d", "",
		"Bundle release date (YYYY-MM-DD), default: latest")
	cmd.Flags().StringVarP(&opts.OutputDir, "output-dir", "o", ".",
		"Output directory for downloaded files (use '-' to print to stdout)")

	return cmd
}

// Run executes the download command.
func Run(ctx context.Context, o *Opts) error {
	if o.OutputDir != "-" && !utils.DirExists(o.OutputDir) {
		return fmt.Errorf("output directory %s does not exist", o.OutputDir)
	}

	var bundlePath string
	if o.OutputDir != "-" {
		bundlePath = filepath.Join(o.OutputDir, bundleFilename)

		if utils.FileExists(bundlePath) && !o.Force {
			cli.DisplayWarning("File %s already exists.", bundlePath)
			if !cli.PromptConfirmation("Override?") {
				fmt.Println()
				return fmt.Errorf("download cancelled")
			}
			fmt.Println()
		}
	}

	if o.Date == "" {
		display(o, "Fetching latest release...")
	} else {
		display(o, "Fetching release %s...", o.Date)
	}

	cfg := apiv1beta.GetConfig{
		Date:       o.Date,
		SkipVerify: o.SkipVerify,
	}

	trustedBundle, err := apiv1beta.GetTrustedBundle(ctx, cfg)
	if err != nil {
		if errors.Is(err, apiv1beta.ErrBundleVerificationFailed) {
			cli.DisplayError("❌ Bundle verification failed")
		}
		return err
	}

	if o.SkipVerify {
		cli.DisplayWarning("⚠️  Verification skipped (--skip-verify)")
	} else {
		displaySuccess(o, "✅ Bundle verified")
	}

	if o.OutputDir == "-" {
		_, err = os.Stdout.Write(trustedBundle.GetRaw())
		return err
	}

	if err := os.WriteFile(bundlePath, trustedBundle.GetRaw(), 0644); err != nil {
		return fmt.Errorf("failed to write bundle to disk: %w", err)
	}

	cli.DisplaySuccess("✅ Downloaded bundle to %s", bundlePath)

	return nil
}

func display(o *Opts, msg string, args ...any) {
	if o.OutputDir == "-" {
		return
	}
	fmt.Println(fmt.Sprintf(msg, args...))
}

func displaySuccess(o *Opts, msg string, args ...any) {
	if o.OutputDir == "-" {
		return
	}
	cli.DisplaySuccess(msg, args...)
}
