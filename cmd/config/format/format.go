package format

import (
	"fmt"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config/format"
	"github.com/spf13/cobra"
)

var (
	configPath string
	dryRun     bool
)

// NewCommand creates the format command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "format",
		Short: "Format TPM roots configuration file",
		Long: `Format a TPM roots YAML configuration file with consistent styling.

The formatter applies the following rules:
  - Sort vendors alphabetically by ID
  - Sort certificates within each vendor alphabetically by name
  - URL-encode certificate URLs (if needed)
  - Format fingerprints to uppercase with colon separators (AA:BB:CC:DD)
  - Add double quotes to all string values

The file is formatted in-place unless --dry-run is specified.

With --dry-run, the command checks if formatting would change the file and exits with:
  - Exit code 0: File is already properly formatted
  - Exit code 1: File needs formatting`,
		Example: `  # Format the default config file
  tpmtb config format

  # Format a specific config file
  tpmtb config format --config custom-roots.yaml

  # Check if a file needs formatting (dry-run mode)
  tpmtb config format --dry-run`,
		SilenceUsage: true,
		RunE:         run,
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", ".tpm-roots.yaml",
		"Path to TPM roots configuration file")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"Check if file needs formatting without modifying it")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	formatter := format.NewFormatter()

	if dryRun {
		needsFormatting, err := formatter.NeedsFormatting(configPath)
		if err != nil {
			return fmt.Errorf("failed to check formatting: %w", err)
		}

		if needsFormatting {
			fmt.Printf("File needs formatting: %s\n", configPath)
			return fmt.Errorf("file is not properly formatted")
		}

		fmt.Printf("File is properly formatted: %s\n", configPath)
		return nil
	}

	if err := formatter.FormatFile(configPath, configPath); err != nil {
		return fmt.Errorf("failed to format file: %w", err)
	}

	fmt.Printf("Formatted: %s\n", configPath)
	return nil
}
