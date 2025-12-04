package config

import (
	"github.com/loicsikidi/tpm-ca-certificates/cmd/config/certificates"
	"github.com/loicsikidi/tpm-ca-certificates/cmd/config/format"
	"github.com/loicsikidi/tpm-ca-certificates/cmd/config/validate"
	"github.com/loicsikidi/tpm-ca-certificates/cmd/config/vendors"
	"github.com/spf13/cobra"
)

// NewCommand creates the config command with its subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "manage TPM roots configuration file",
		Long:  `Format, validate, and manage certificates and vendors in the configuration file.`,
	}

	cmd.AddCommand(format.NewCommand())
	cmd.AddCommand(validate.NewCommand())
	cmd.AddCommand(certificates.NewCommand())
	cmd.AddCommand(vendors.NewCommand())

	return cmd
}
