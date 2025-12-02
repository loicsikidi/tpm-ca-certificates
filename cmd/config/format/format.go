package format

import (
	"fmt"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config/format"
	"github.com/spf13/cobra"
)

var configPath string

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

The file is formatted in-place.`,
		Example: `  # Format the default config file
  tpmtb config format

  # Format a specific config file
  tpmtb config format --config custom-roots.yaml`,
		SilenceUsage: true,
		RunE:         run,
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", ".tpm-roots.yaml",
		"Path to TPM roots configuration file")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	formatter := format.NewFormatter()
	if err := formatter.FormatFile(configPath, configPath); err != nil {
		return fmt.Errorf("failed to format file: %w", err)
	}

	fmt.Printf("Formatted: %s\n", configPath)
	return nil
}
