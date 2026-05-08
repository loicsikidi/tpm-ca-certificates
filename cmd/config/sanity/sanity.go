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
	osExit        = os.Exit // Allow mocking in tests
	checkerGetter = sanity.NewChecker
)

// Opts represents the configuration options for the sanity command.
type Opts struct {
	ConfigPath string
	Quiet      bool
	Workers    int
	Threshold  int
}

// Check validates the sanity command options.
func (o *Opts) Check() error {
	if o.Workers > concurrency.MaxWorkers {
		return fmt.Errorf("concurrency value %d exceeds maximum allowed (%d)", o.Workers, concurrency.MaxWorkers)
	}
	return nil
}

// NewCommand creates the sanity command.
func NewCommand() *cobra.Command {
	o := &Opts{}

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
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, o)
		},
	}

	cmd.Flags().StringVarP(&o.ConfigPath, "config", "c", ".tpm-roots.yaml",
		"Path to TPM roots configuration file")
	cmd.Flags().BoolVarP(&o.Quiet, "quiet", "q", false,
		"Suppress output, only return exit code")
	cmd.Flags().IntVarP(&o.Workers, "workers", "j", 0,
		fmt.Sprintf("Number of workers to use (0=auto-detect, max=%d)", concurrency.MaxWorkers))
	cmd.Flags().IntVarP(&o.Threshold, "threshold", "t", defaultThreshold,
		"Days threshold for expiration warnings (default: 365 days)")

	return cmd
}

func run(_ *cobra.Command, _ []string, o *Opts) error {
	if err := o.Check(); err != nil {
		return err
	}

	cfg, err := config.LoadConfig(o.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	checker := checkerGetter()
	result, err := checker.Check(cfg, o.Workers, o.Threshold)
	if err != nil {
		return fmt.Errorf("sanity check failed: %w", err)
	}

	if !result.HasIssues() {
		if !o.Quiet {
			cli.DisplaySuccess("✅ All certificates passed sanity checks.")
		}
		return nil
	}

	if !o.Quiet {
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
