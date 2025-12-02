package validate

import (
	"fmt"
	"os"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config/validate"
	"github.com/spf13/cobra"
)

var (
	configPath string
	quiet      bool
	osExit     = os.Exit // Allow mocking in tests
)

// NewCommand creates the validate command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate TPM roots configuration file",
		Long: `Validate a TPM roots YAML configuration file.

The validator checks:
  - Vendor IDs are valid according to TCG TPM Vendor ID Registry
  - Vendors are sorted alphabetically by ID
  - Certificates within each vendor are sorted alphabetically by name
  - URLs are properly URL-encoded and use HTTPS scheme
  - Fingerprints are formatted in uppercase with colon separators (AA:BB:CC:DD)
  - String values are double-quoted

Returns exit code 1 if validation errors are found.
Shows up to 10 validation errors with line numbers.`,
		Example: `  # Validate the default config file
  tpmtb config validate

  # Validate a specific config file
  tpmtb config validate --config custom-roots.yaml`,
		SilenceUsage: true,
		RunE:         run,
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", ".tpm-roots.yaml",
		"Path to TPM roots configuration file")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false,
		"Suppress output, only return exit code")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	validator := validate.NewYAMLValidator()
	errors, err := validator.ValidateFile(configPath)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if len(errors) == 0 {
		if !quiet {
			fmt.Printf("✅  %s is valid\n", configPath)
		}
		return nil
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "❌ %s has validation errors:\n\n", configPath)
		for _, verr := range errors {
			fmt.Fprintf(os.Stderr, "  Line %d: %s\n", verr.Line, verr.Message)
		}

		if len(errors) >= 10 {
			fmt.Fprintf(os.Stderr, "\n(showing first 10 errors)\n")
		}
	}

	osExit(1)
	return nil
}
