package generate

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/concurrency"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/git"
	"github.com/spf13/cobra"
)

// Opts represents the configuration options for the generate command.
type Opts struct {
	ConfigPath string
	OutputPath string
	Workers    int
	Date       string
	Commit     string
	Type       string
}

// NewCommand creates the generate command.
func NewCommand() *cobra.Command {
	o := &Opts{}

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
		RunE: func(cmd *cobra.Command, args []string) error {
			return Run(cmd.Context(), o)
		},
	}

	cmd.Flags().StringVarP(&o.ConfigPath, "config", "c", ".tpm-roots.yaml",
		"Path to TPM roots configuration file")
	cmd.Flags().StringVarP(&o.OutputPath, "output", "o", "",
		"Output file path (default: stdout)")
	cmd.Flags().IntVarP(&o.Workers, "workers", "j", 0,
		fmt.Sprintf("Number of workers to use (0=auto-detect, max=%d)", concurrency.MaxWorkers))
	cmd.Flags().StringVarP(&o.Date, "date", "d", "",
		"Bundle generation date in YYYY-MM-DD format (default: auto-detect from git)")
	cmd.Flags().StringVar(&o.Commit, "commit", "",
		"Git commit hash (default: auto-detect from git)")
	cmd.Flags().StringVarP(&o.Type, "type", "t", "",
		"Bundle type: root or intermediate (default: auto-detect from config filename)")

	return cmd
}

func Run(ctx context.Context, o *Opts) error {
	cfg, err := config.LoadConfigWithDynamicURIResolution(o.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	if o.Workers > concurrency.MaxWorkers {
		return fmt.Errorf("concurrency value %d exceeds maximum allowed (%d)", o.Workers, concurrency.MaxWorkers)
	}

	bundleType, err := resolveBundleType(o.Type, o.ConfigPath)
	if err != nil {
		return fmt.Errorf("failed to resolve bundle type: %w", err)
	}

	if (o.Date != "" && o.Commit == "") || (o.Date == "" && o.Commit != "") {
		return fmt.Errorf("both --date and --commit flags must be provided together")
	}

	var bundleDate, bundleCommit string

	if o.Date != "" && o.Commit != "" {
		if err := bundle.ValidateDate(o.Date); err != nil {
			return fmt.Errorf("invalid --date flag: %w", err)
		}
		if err := bundle.ValidateCommit(o.Commit); err != nil {
			return fmt.Errorf("invalid --commit flag: %w", err)
		}
		bundleDate = o.Date
		bundleCommit = o.Commit
	} else {
		// Auto-detect from git
		bundleDate, bundleCommit, err = resolveGitMetadata()
		if err != nil {
			return fmt.Errorf("failed to resolve git metadata: %w", err)
		}
	}

	gen := bundle.NewGenerator()
	pemBundle, err := gen.GenerateWithMetadata(cfg, o.Workers, o.OutputPath, bundleDate, bundleCommit, bundleType)
	if err != nil {
		return fmt.Errorf("failed to generate bundle: %w", err)
	}

	if o.OutputPath == "" {
		fmt.Println(pemBundle)
	} else {
		if err := os.WriteFile(o.OutputPath, []byte(pemBundle), 0644); err != nil {
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
	if err := bundle.ValidateDate(info.Tag); err != nil {
		return "", "", fmt.Errorf("git tag %q is not in YYYY-MM-DD format (use --date and --commit flags to specify manually): %w", info.Tag, err)
	}
	if err := bundle.ValidateCommit(info.Commit); err != nil {
		return "", "", fmt.Errorf("git commit %q is not a valid commit hash (use --date and --commit flags to specify manually): %w", info.Commit, err)
	}

	return info.Tag, info.Commit, nil
}

// resolveBundleType determines the bundle type based on the --type flag or config filename.
//
// Priority:
//  1. If typeFlag is provided (non-empty), use it
//  2. Otherwise, infer from config filename:
//     - ".tpm-intermediates.yaml" → intermediate
//     - anything else → root
func resolveBundleType(typeFlag, configPath string) (bundle.BundleType, error) {
	// If type is explicitly provided, use it
	if typeFlag != "" {
		bundleType := bundle.BundleType(typeFlag)
		if err := bundleType.Validate(); err != nil {
			return "", err
		}
		return bundleType, nil
	}

	// Auto-detect from config filename (check basename only)
	basename := filepath.Base(configPath)
	if basename == ".tpm-intermediates.yaml" {
		return bundle.TypeIntermediate, nil
	}

	return bundle.TypeRoot, nil
}
