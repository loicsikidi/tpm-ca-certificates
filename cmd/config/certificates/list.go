package certificates

import (
	"fmt"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/spf13/cobra"
)

type listOptions struct {
	configPath string
	vendorID   string
}

func newListCommand() *cobra.Command {
	opts := &listOptions{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List certificates in the configuration",
		Long: `List all certificates in the configuration file.

If a vendor ID is specified, only certificates for that vendor will be listed.`,
		Example: `  # List all certificates
  tpmtb config certificates list

  # List certificates for a specific vendor
  tpmtb config certificates list -i STM`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.configPath, "config", "c", ".tpm-roots.yaml", "Path to the configuration file")
	cmd.Flags().StringVarP(&opts.vendorID, "vendor-id", "i", "", "Filter by vendor ID")

	return cmd
}

func runList(opts *listOptions) error {
	cfg, err := config.LoadConfig(opts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	vendors := cfg.Vendors
	if opts.vendorID != "" {
		found := false
		for _, v := range cfg.Vendors {
			if v.ID == opts.vendorID {
				vendors = []config.Vendor{v}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("vendor with ID '%s' not found", opts.vendorID)
		}
	}

	for _, vendor := range vendors {
		fmt.Printf("Vendor: %s (ID: %s)\n", vendor.Name, vendor.ID)
		fmt.Println(strings.Repeat("-", 80))

		if len(vendor.Certificates) == 0 {
			fmt.Println("  No certificates")
			fmt.Println()
			continue
		}

		for _, cert := range vendor.Certificates {
			fmt.Printf("  Certificate: %s\n", cert.Name)
			fmt.Printf("    URL: %s\n", cert.URL)

			fp := cert.Validation.Fingerprint
			hasFingerprints := false

			if fp.SHA1 != "" {
				fmt.Printf("    SHA1:   %s\n", fp.SHA1)
				hasFingerprints = true
			}
			if fp.SHA256 != "" {
				fmt.Printf("    SHA256: %s\n", fp.SHA256)
				hasFingerprints = true
			}
			if fp.SHA384 != "" {
				fmt.Printf("    SHA384: %s\n", fp.SHA384)
				hasFingerprints = true
			}
			if fp.SHA512 != "" {
				fmt.Printf("    SHA512: %s\n", fp.SHA512)
				hasFingerprints = true
			}

			if !hasFingerprints {
				fmt.Println("    No fingerprints")
			}

			fmt.Println()
		}
	}

	return nil
}
