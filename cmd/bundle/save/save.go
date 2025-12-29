package save

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
	"github.com/spf13/cobra"
)

// Opts represents the configuration options for the save command.
type Opts struct {
	Date       string
	VendorIDs  []string
	OutputDir  string
	Force      bool
	LocalCache bool
}

// NewCommand creates the save command.
func NewCommand() *cobra.Command {
	o := &Opts{}

	cmd := &cobra.Command{
		Use:   "save",
		Short: "save a TPM trust bundle with offline verification support",
		Long: `Save a TPM trust bundle with all assets required for offline verification.

This creates a complete offline-capable cache that can be used later for
verification without network access.`,
		Example: `  # Save the latest bundle to current directory
  tpmtb bundle save

  # Save a specific bundle by date
  tpmtb bundle save --date 2025-12-05

  # Save to a specific directory
  tpmtb bundle save --output-dir /path/to/cache

  # Save to the local cache directory
  tpmtb bundle save --local-cache

  # Save bundle filtered by specific vendors
  tpmtb bundle save --vendor-ids IFX,NTC --output-dir /tmp/cache`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return Run(cmd.Context(), o)
		},
	}

	cmd.Flags().StringVarP(&o.Date, "date", "d", "",
		"Bundle release date (YYYY-MM-DD), default: latest")
	cmd.Flags().StringSliceVar(&o.VendorIDs, "vendor-ids", nil,
		"Comma-separated list of vendor IDs to filter (e.g., IFX,NTC,STM,INTC)")
	cmd.Flags().StringVarP(&o.OutputDir, "output-dir", "o", ".",
		"Output directory for saved files")
	cmd.Flags().BoolVarP(&o.Force, "force", "f", false,
		"Overwrite existing files without prompting")
	cmd.Flags().BoolVar(&o.LocalCache, "local-cache", false,
		"Save assets to local cache directory (default: false)")

	return cmd
}

// Run executes the save command with the given options.
func Run(ctx context.Context, o *Opts) error {
	if !utils.DirExists(o.OutputDir) {
		return fmt.Errorf("output directory %s does not exist", o.OutputDir)
	}

	var parsedVendorIDs []apiv1beta.VendorID
	for _, vid := range o.VendorIDs {
		vendorID := apiv1beta.VendorID(vid)
		if err := vendorID.Validate(); err != nil {
			return fmt.Errorf("invalid vendor ID %q: %w", vid, err)
		}
		parsedVendorIDs = append(parsedVendorIDs, vendorID)
	}

	if !o.Force && !o.LocalCache {
		if err := checkExistingFiles(o.OutputDir); err != nil {
			return err
		}
	}

	if o.Date == "" {
		cli.Display("Fetching latest release...")
	} else {
		cli.Display("Fetching release %s...", o.Date)
	}

	cfg := apiv1beta.SaveConfig{
		Date:      o.Date,
		VendorIDs: parsedVendorIDs,
	}

	resp, err := apiv1beta.SaveTrustedBundle(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to save bundle: %w", err)
	}

	cli.DisplaySuccess("✅ Bundle verified and assets downloaded")

	targetDir := o.OutputDir
	if o.LocalCache {
		targetDir = cache.CacheDir()
	}
	if err := resp.Persist(targetDir); err != nil {
		return fmt.Errorf("failed to persist bundle: %w", err)
	}

	cli.DisplaySuccess("✅ Saved bundle to %s", targetDir)

	cli.Display("Saved files:")
	cli.Display("  - %s", apiv1beta.CacheRootBundleFilename)
	if len(resp.IntermediateBundle) > 0 {
		cli.Display("  - %s", apiv1beta.CacheIntermediateBundleFilename)
	}
	cli.Display("  - %s", apiv1beta.CacheChecksumsFilename)
	cli.Display("  - %s", apiv1beta.CacheChecksumsSigFilename)
	cli.Display("  - %s", apiv1beta.CacheProvenanceFilename)
	cli.Display("  - %s", apiv1beta.CacheTrustedRootFilename)
	cli.Display("  - %s", apiv1beta.CacheConfigFilename)

	return nil
}

func checkExistingFiles(outputDir string) error {
	var existingFiles []string
	for _, filename := range apiv1beta.CacheFilenames {
		filePath := filepath.Join(outputDir, filename)
		if utils.FileExists(filePath) {
			existingFiles = append(existingFiles, filename)
		}
	}

	if len(existingFiles) > 0 {
		cli.DisplayWarning("The following files already exist in %s:", outputDir)
		for _, filename := range existingFiles {
			cli.Display("  - %s", filename)
		}
		if !cli.PromptConfirmation("Override?") {
			fmt.Println() // Add newline for clean output after prompt
			return fmt.Errorf("save cancelled")
		}
		fmt.Println() // Add newline for clean output after prompt
	}
	return nil
}
