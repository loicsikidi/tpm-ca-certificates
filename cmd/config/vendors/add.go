package vendors

import (
	"fmt"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/format"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/vendors"

	"github.com/spf13/cobra"
)

type addOptions struct {
	configPath string
	id         string
	name       string
}

func newAddCommand() *cobra.Command {
	opts := &addOptions{}

	cmd := &cobra.Command{
		Use:   "add <id> <name>",
		Short: "add a new vendor to the configuration file",
		Long: `Add a new vendor to the configuration file.

The vendor will be added with an empty certificate list and inserted in alphabetical order by ID.`,
		Example: `  # Add a new vendor
  tpmtb config vendors add INTC "Intel Corporation"

  # Add a vendor with custom config file
  tpmtb config vendors add -c custom.yaml AMD "Advanced Micro Devices"`,
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.id = args[0]
			opts.name = args[1]
			return runAddVendor(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.configPath, "config", "c", ".tpm-roots.yaml", "Path to the configuration file")

	return cmd
}

func runAddVendor(opts *addOptions) error {
	if err := vendors.ValidateVendorID(opts.id); err != nil {
		return err
	}

	cfg, err := config.LoadConfigWithDynamicURIResolution(opts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	for _, v := range cfg.Vendors {
		if v.ID == opts.id {
			return fmt.Errorf("vendor with ID '%s' already exists", opts.id)
		}
	}

	newVendor := config.Vendor{
		ID:           opts.id,
		Name:         opts.name,
		Certificates: []config.Certificate{},
	}

	// Add vendor to the list (formatter will sort it)
	cfg.Vendors = append(cfg.Vendors, newVendor)

	if err := config.SaveConfig(opts.configPath, cfg); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	formatter := format.NewFormatter()
	if err := formatter.FormatFile(opts.configPath, opts.configPath); err != nil {
		return fmt.Errorf("failed to format configuration: %w", err)
	}

	fmt.Printf("✅ Vendor '%s' (%s) added successfully\n", opts.name, opts.id)
	return nil
}
