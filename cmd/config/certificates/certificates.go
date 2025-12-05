package certificates

import (
	"github.com/spf13/cobra"
)

// NewCommand creates the certificates command with its subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificates",
		Short: "manage certificates in the TPM roots configuration",
		Long:  `Add, remove, or list certificates in the .tpm-roots.yaml configuration file.`,
	}

	cmd.AddCommand(newAddCommand())
	cmd.AddCommand(newRemoveCommand())
	cmd.AddCommand(newListCommand())

	return cmd
}
