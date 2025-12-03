package vendors

import (
	"github.com/spf13/cobra"
)

// NewCommand creates the vendors command with its subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vendors",
		Short: "Manage vendors in the TPM roots configuration",
		Long:  `List or manage vendors in the configuration file.`,
	}

	cmd.AddCommand(newListCommand())
	cmd.AddCommand(newAddCommand())

	return cmd
}
