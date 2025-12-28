package download

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
	"github.com/spf13/cobra"
)

// Opts holds the configuration for the download command.
type Opts struct {
	SkipVerify bool
	Force      bool
	Date       string
	OutputDir  string
	Type       string
	CacheDir   string
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

  # Download only the root bundle
  tpmtb bundle download --type root

  # Download only the intermediate bundle
  tpmtb bundle download --type intermediate

  # Download without verification
  tpmtb bundle download --skip-verify

  # Download and overwrite existing file without prompting
  tpmtb bundle download --force

  # Download to a specific directory
  tpmtb bundle download --output-dir /tmp

  # Print bundle to stdout (requires --type)
  tpmtb bundle download --output-dir - --type root`,
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
	cmd.Flags().StringVarP(&opts.Type, "type", "t", "",
		"Bundle type: root, intermediate, or empty for both (default: download both bundles when available)")

	return cmd
}

// bundleInfo holds information about a bundle to save on disk.
type bundleInfo struct {
	data     []byte
	filename string
	label    string
}

// Run executes the download command.
func Run(ctx context.Context, o *Opts) error {
	if o.OutputDir != "-" && !utils.DirExists(o.OutputDir) {
		return fmt.Errorf("output directory %s does not exist", o.OutputDir)
	}

	// Validate and parse bundle type
	bundleType := bundle.BundleType(o.Type)
	if err := bundleType.Validate(); err != nil {
		return err
	}

	// Validate stdout usage
	if o.OutputDir == "-" && bundleType == bundle.TypeUnspecified {
		return fmt.Errorf("when using stdout (--output-dir -), you must specify --type (root or intermediate)")
	}

	if o.Date == "" {
		display(o, "Fetching latest release...")
	} else {
		display(o, "Fetching release %s...", o.Date)
	}

	cfg := apiv1beta.GetConfig{
		Date:       o.Date,
		SkipVerify: o.SkipVerify,
		CachePath:  o.CacheDir,
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

	var bundleInfos []bundleInfo
	switch bundleType {
	case bundle.TypeRoot:
		bundleInfos = []bundleInfo{
			{
				data:     trustedBundle.GetRawRoot(),
				filename: apiv1beta.CacheRootBundleFilename,
				label:    "root",
			},
		}
	case bundle.TypeIntermediate:
		intermediateData := trustedBundle.GetRawIntermediate()
		if len(intermediateData) == 0 {
			return fmt.Errorf("intermediate bundle not available for this release")
		}
		bundleInfos = []bundleInfo{
			{
				data:     intermediateData,
				filename: apiv1beta.CacheIntermediateBundleFilename,
				label:    "intermediate",
			},
		}
	case bundle.TypeUnspecified:
		// Save both bundles when available
		bundleInfos = []bundleInfo{
			{
				data:     trustedBundle.GetRawRoot(),
				filename: apiv1beta.CacheRootBundleFilename,
				label:    "root",
			},
		}
		if intermediateData := trustedBundle.GetRawIntermediate(); len(intermediateData) > 0 {
			bundleInfos = append(bundleInfos, bundleInfo{
				data:     intermediateData,
				filename: apiv1beta.CacheIntermediateBundleFilename,
				label:    "intermediate",
			})
		}
	}

	// Handle stdout output
	if o.OutputDir == "-" {
		_, err = os.Stdout.Write(bundleInfos[0].data)
		return err
	}

	// Check for existing files before writing
	if !o.Force {
		for _, info := range bundleInfos {
			bundlePath := filepath.Join(o.OutputDir, info.filename)
			if utils.FileExists(bundlePath) {
				cli.DisplayWarning("File %s already exists.", bundlePath)
				if !cli.PromptConfirmation("Override?") {
					fmt.Println()
					return fmt.Errorf("download cancelled")
				}
				fmt.Println()
				break
			}
		}
	}

	for _, info := range bundleInfos {
		bundlePath := filepath.Join(o.OutputDir, info.filename)
		if err := os.WriteFile(bundlePath, info.data, 0644); err != nil {
			return fmt.Errorf("failed to write %s bundle to disk: %w", info.label, err)
		}
		cli.DisplaySuccess("✅ Downloaded %s bundle to %s", info.label, bundlePath)
	}

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
