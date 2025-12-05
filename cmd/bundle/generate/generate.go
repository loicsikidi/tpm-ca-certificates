package generate

import (
	"fmt"
	"os"
	"regexp"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/concurrency"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/git"
	"github.com/spf13/cobra"
)

var (
	configPath string
	outputPath string
	workers    int
	date       string
	commit     string
)

// NewCommand creates the generate command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "generate TPM trust bundle from a configuration file",
		Long: `Generate a PEM-encoded trust bundle by downloading and validating TPM root certificates.

The command reads vendor certificate configurations from a YAML file, downloads each certificate,
validates its fingerprint (SHA1/SHA256/SHA384/SHA512), and outputs a concatenated PEM bundle.

Important: the generation is deterministic. Given the same configuration and inputs,
the output bundle will always be the same. 

By default, output is written to stdout. Use --output to write to a file instead.`,
		Example: `  # Generate bundle to stdout
  tpmtb generate

  # Generate bundle to file
  tpmtb generate --output tpm-ca-certificates.pem

  # Use custom config file
  tpmtb generate --config custom-roots.yaml --output bundle.pem`,
		SilenceUsage: true,
		RunE:         run,
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", ".tpm-roots.yaml",
		"Path to TPM roots configuration file")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "",
		"Output file path (default: stdout)")
	cmd.Flags().IntVarP(&workers, "workers", "j", 0,
		fmt.Sprintf("Number of workers to use (0=auto-detect, max=%d)", concurrency.MaxWorkers))
	cmd.Flags().StringVar(&date, "date", "",
		"Bundle generation date in YYYY-MM-DD format (default: auto-detect from git)")
	cmd.Flags().StringVar(&commit, "commit", "",
		"Git commit hash (default: auto-detect from git)")

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

	if (date != "" && commit == "") || (date == "" && commit != "") {
		return fmt.Errorf("both --date and --commit flags must be provided together")
	}

	var bundleDate, bundleCommit string

	if date != "" && commit != "" {
		if err := validateDate(date); err != nil {
			return fmt.Errorf("invalid --date flag: %w", err)
		}
		if err := validateCommit(commit); err != nil {
			return fmt.Errorf("invalid --commit flag: %w", err)
		}
		bundleDate = date
		bundleCommit = commit
	} else {
		// Auto-detect from git
		bundleDate, bundleCommit, err = resolveGitMetadata()
		if err != nil {
			return fmt.Errorf("failed to resolve git metadata: %w", err)
		}
	}

	gen := bundle.NewGenerator()
	pemBundle, err := gen.GenerateWithMetadata(cfg, workers, outputPath, bundleDate, bundleCommit)
	if err != nil {
		return fmt.Errorf("failed to generate bundle: %w", err)
	}

	if outputPath == "" {
		fmt.Println(pemBundle)
	} else {
		if err := os.WriteFile(outputPath, []byte(pemBundle), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
	}

	return nil
}

// resolveGitMetadata auto-detects date and commit from git repository.
// It assumes this function is only called when --date and --commit flags are not provided.
// Returns date (from git tag in YYYY-MM-DD format) and commit hash.
func resolveGitMetadata() (string, string, error) {
	info, err := git.GetInfo(".")
	if err != nil {
		return "", "", fmt.Errorf("failed to get git info (use --date and --commit flags to specify manually): %w", err)
	}

	// Use tag as date (must be in YYYY-MM-DD format)
	if info.Tag == "" {
		return "", "", fmt.Errorf("no git tag found for current commit (tag is required in YYYY-MM-DD format, or use --date and --commit flags)")
	}
	if err := validateDate(info.Tag); err != nil {
		return "", "", fmt.Errorf("git tag %q is not in YYYY-MM-DD format (use --date and --commit flags to specify manually): %w", info.Tag, err)
	}
	if err := validateCommit(info.Commit); err != nil {
		return "", "", fmt.Errorf("git commit %q is not a valid commit hash (use --date and --commit flags to specify manually): %w", info.Commit, err)
	}

	return info.Tag, info.Commit, nil
}

// validateDate checks if the date is in YYYY-MM-DD format.
func validateDate(d string) error {
	dateRegex := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	if !dateRegex.MatchString(d) {
		return fmt.Errorf("date must be in YYYY-MM-DD format, got: %s", d)
	}
	return nil
}

// validateCommit checks if the commit is a valid 40-character hex string.
func validateCommit(c string) error {
	commitRegex := regexp.MustCompile(`^[0-9a-f]{40}$`)
	if !commitRegex.MatchString(c) {
		return fmt.Errorf("commit must be a 40-character hex string, got: %s", c)
	}
	return nil
}
