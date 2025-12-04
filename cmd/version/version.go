package version

import (
	"fmt"

	"github.com/loicsikidi/tpm-ca-certificates/internal/version"
	"github.com/spf13/cobra"
)

// NewCommand creates the version command.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "version",
		Short:        "display the current version of the cli",
		Long:         `Display detailed version information including revision, version, build time, and dirty status.`,
		SilenceUsage: true,
		Run:          run,
	}

	return cmd
}

func run(cmd *cobra.Command, args []string) {
	fmt.Println(version.Get())
}
