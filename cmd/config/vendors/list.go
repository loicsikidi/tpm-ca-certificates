package vendors

import (
	"fmt"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/spf13/cobra"
)

type listOptions struct {
	configPath string
	short      bool
}

func newListCommand() *cobra.Command {
	opts := &listOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "list vendors from the configuration file",
		Long: `List all vendors in the configuration file.

By default, displays a formatted table with vendor details.
Use --short for a simple list of vendor IDs and names.`,
		Example: `  # List all vendors in table format
  tpmtb config vendors list

  # List vendors in simple format
  tpmtb config vendors list --short`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.configPath, "config", "c", ".tpm-roots.yaml", "Path to the configuration file")
	cmd.Flags().BoolVar(&opts.short, "short", false, "Display simple list of vendor IDs and names")

	return cmd
}

func runList(opts *listOptions) error {
	cfg, err := config.LoadConfig(opts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if len(cfg.Vendors) == 0 {
		fmt.Println("No vendors found")
		return nil
	}

	if opts.short {
		for _, vendor := range cfg.Vendors {
			fmt.Printf("%s (%s)\n", vendor.Name, vendor.ID)
		}
		return nil
	}

	displayTable(cfg.Vendors)
	return nil
}

func displayTable(vendors []config.Vendor) {
	// Calculate column widths
	maxIDLen := len("VENDOR ID")
	maxNameLen := len("VENDOR NAME")

	for _, vendor := range vendors {
		if len(vendor.ID) > maxIDLen {
			maxIDLen = len(vendor.ID)
		}
		if len(vendor.Name) > maxNameLen {
			maxNameLen = len(vendor.Name)
		}
	}

	// Add padding
	idWidth := maxIDLen + 2
	nameWidth := maxNameLen + 2
	certsWidth := len("CERTIFICATES") + 2

	// Print header
	fmt.Printf("%-*s %-*s %-*s\n", idWidth, "VENDOR ID", nameWidth, "VENDOR NAME", certsWidth, "CERTIFICATES")
	fmt.Println(strings.Repeat("-", idWidth+nameWidth+certsWidth))

	// Print rows
	for _, vendor := range vendors {
		fmt.Printf("%-*s %-*s %-*d\n",
			idWidth, vendor.ID,
			nameWidth, vendor.Name,
			certsWidth, len(vendor.Certificates))
	}
}
