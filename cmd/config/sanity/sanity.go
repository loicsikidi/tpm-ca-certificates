package sanity

import (
	"fmt"
	"os"

	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/loicsikidi/tpm-ca-certificates/internal/concurrency"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/sanity"
	"github.com/spf13/cobra"
)

const (
	defaultThreshold = 365 // days
	maxErrors        = 10
)

var (
	configPath    string
	quiet         bool
	workers       int
	threshold     int
	osExit        = os.Exit // Allow mocking in tests
	checkerGetter = sanity.NewChecker
)

// NewCommand creates the sanity command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sanity",
		Short: "perform sanity checks on the configuration file",
		Long: `Perform sanity checks on TPM root certificates in the configuration file.

The sanity checker:
  - Downloads each certificate from its URL
  - Validates the certificate fingerprint matches the configuration
  - Checks if certificates are expired or expiring soon (within threshold days)

Returns exit code 1 if any issues are found.
Shows up to 10 validation errors and 10 expiration warnings.`,
		Example: `  # Check all certificates with default settings (180 days threshold)
  tpmtb config sanity

  # Check with custom threshold
  tpmtb config sanity --threshold 30

  # Check with specific config file
  tpmtb config sanity --config custom-roots.yaml

  # Quiet mode (only return exit code)
  tpmtb config sanity --quiet`,
		SilenceUsage: true,
		RunE:         run,
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", ".tpm-roots.yaml",
		"Path to TPM roots configuration file")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false,
		"Suppress output, only return exit code")
	cmd.Flags().IntVarP(&workers, "workers", "j", 0,
		fmt.Sprintf("Number of workers to use (0=auto-detect, max=%d)", concurrency.MaxWorkers))
	cmd.Flags().IntVarP(&threshold, "threshold", "t", defaultThreshold,
		"Days threshold for expiration warnings (default: 365 days)")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if workers > concurrency.MaxWorkers {
		return fmt.Errorf("concurrency value %d exceeds maximum allowed (%d)", workers, concurrency.MaxWorkers)
	}

	checker := checkerGetter()
	result, err := checker.Check(cfg, workers, threshold)
	if err != nil {
		return fmt.Errorf("sanity check failed: %w", err)
	}

	if !result.HasIssues() {
		if !quiet {
			cli.DisplaySuccess("✅ All certificates passed sanity checks.")
		}
		return nil
	}

	if !quiet {
		displayResults(result)
	}

	osExit(1)
	return nil
}

func displayResults(result *sanity.Result) {
	if len(result.ValidationErrors) > 0 {
		cli.DisplayError("❌ Certificate validation errors:")
		displayCount := min(len(result.ValidationErrors), maxErrors)
		for i := range displayCount {
			cli.DisplayStderr("%s\n", result.ValidationErrors[i].String())
		}
		if len(result.ValidationErrors) > maxErrors {
			cli.DisplayStderr("(showing first %d errors)\n\n", maxErrors)
		}
	}

	// Display expiration warnings
	if len(result.ExpirationWarnings) > 0 {
		cli.DisplayWarning("⚠️  Certificate expiration warnings:")
		displayCount := min(len(result.ExpirationWarnings), maxErrors)
		for i := range displayCount {
			cli.DisplayStderr("%s\n", result.ExpirationWarnings[i].String())
		}
		if len(result.ExpirationWarnings) > maxErrors {
			cli.DisplayStderr("(showing first %d warnings)\n", maxErrors)
		}
	}
}
