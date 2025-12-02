package certificates

import (
	"fmt"
	"strings"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/format"
	"github.com/spf13/cobra"
)

type removeOptions struct {
	configPath string
	vendorID   string
	name       string
}

func newRemoveCommand() *cobra.Command {
	opts := &removeOptions{}

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove a certificate from a vendor in the configuration",
		Long: `Remove a certificate from a vendor's certificate list in the configuration file.

The certificate is identified by its name (case-insensitive match).`,
		Example: `  # Remove a certificate from a vendor
  tpmtb config certificates remove -i STM -n "STSAFE ECC Root CA 02"`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRemove(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.configPath, "config", "c", ".tpm-roots.yaml", "Path to the configuration file")
	cmd.Flags().StringVarP(&opts.vendorID, "vendor-id", "i", "", "Vendor ID to remove the certificate from")
	cmd.Flags().StringVarP(&opts.name, "name", "n", "", "Name of the certificate to remove")

	cmd.MarkFlagRequired("vendor-id")
	cmd.MarkFlagRequired("name")

	return cmd
}

func runRemove(opts *removeOptions) error {
	cfg, err := config.LoadConfig(opts.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	vendorIdx := -1
	for i, v := range cfg.Vendors {
		if v.ID == opts.vendorID {
			vendorIdx = i
			break
		}
	}
	if vendorIdx == -1 {
		return fmt.Errorf("vendor with ID '%s' not found", opts.vendorID)
	}

	// Find and remove the certificate (case-insensitive)
	certIdx := -1
	searchName := strings.ToLower(opts.name)
	for i, cert := range cfg.Vendors[vendorIdx].Certificates {
		if strings.ToLower(cert.Name) == searchName {
			certIdx = i
			break
		}
	}

	if certIdx == -1 {
		return fmt.Errorf("certificate with name '%s' not found in vendor '%s'", opts.name, opts.vendorID)
	}

	// Remove the certificate
	certName := cfg.Vendors[vendorIdx].Certificates[certIdx].Name
	cfg.Vendors[vendorIdx].Certificates = append(
		cfg.Vendors[vendorIdx].Certificates[:certIdx],
		cfg.Vendors[vendorIdx].Certificates[certIdx+1:]...,
	)

	if err := config.SaveConfig(opts.configPath, cfg); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	formatter := format.NewFormatter()
	if err := formatter.FormatFile(opts.configPath, opts.configPath); err != nil {
		return fmt.Errorf("failed to format configuration: %w", err)
	}

	fmt.Printf("✅ Certificate '%s' removed successfully from vendor '%s'\n", certName, opts.vendorID)
	return nil
}
