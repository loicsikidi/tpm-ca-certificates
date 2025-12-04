package bundle

import (
	"github.com/loicsikidi/tpm-ca-certificates/cmd/bundle/download"
	"github.com/loicsikidi/tpm-ca-certificates/cmd/bundle/generate"
	"github.com/loicsikidi/tpm-ca-certificates/cmd/bundle/list"
	"github.com/loicsikidi/tpm-ca-certificates/cmd/bundle/verify"
	"github.com/spf13/cobra"
)

// NewCommand creates the bundle command with its subcommands.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Manage TPM trust bundles",
		Long:  `Verify, list, and download TPM trust bundles.`,
	}

	cmd.AddCommand(generate.NewCommand())
	cmd.AddCommand(verify.NewCommand())
	cmd.AddCommand(download.NewCommand())
	cmd.AddCommand(list.NewCommand())

	return cmd
}
