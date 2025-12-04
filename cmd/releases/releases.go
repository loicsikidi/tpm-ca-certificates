package releases

import (
	"github.com/loicsikidi/tpm-ca-certificates/cmd/releases/verify"
	"github.com/spf13/cobra"
)

// NewCommand creates the releases command with its subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "releases",
		Short: "Manage TPM trust bundle releases",
		Long:  `Verify, list, and download TPM trust bundle releases.`,
	}

	cmd.AddCommand(verify.NewCommand())

	return cmd
}
