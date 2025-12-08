package validate

import (
	"fmt"
	"os"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/spf13/cobra"
)

var (
	bundlePath string
	quiet      bool
	osExit     = os.Exit // Allow mocking in tests
)

// NewCommand creates the validate command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "validate a TPM trust bundle",
		Long: `Validate a TPM trust bundle file.

Validates the bundle structure and contents according
to internal spec.

Returns exit code 1 if validation errors are found.
Shows up to 10 validation errors with line numbers.`,
		Example: `  # Validate a bundle file
  tpmtb bundle validate tpm-ca-certificates.pem

  # Validate with quiet mode (only exit code)
  tpmtb bundle validate --quiet tpm-ca-certificates.pem`,
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE:         run,
	}

	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false,
		"Suppress output, only return exit code")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	bundlePath = args[0]

	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to read bundle: %w", err)
	}

	validator := bundle.NewBundleValidator()
	errors, err := validator.ValidateBundle(data)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if len(errors) == 0 {
		if !quiet {
			cli.DisplaySuccess("✅ %s is valid", bundlePath)
		}
		return nil
	}

	if !quiet {
		cli.DisplayError("❌ %s has validation errors:", bundlePath)
		for _, verr := range errors {
			cli.DisplayStderr("  Line %d: %s\n", verr.Line, verr.Message)
		}

		if len(errors) >= 10 {
			cli.DisplayStderr("\n(showing first 10 errors)\n")
		}
	}

	osExit(1)
	return nil
}
