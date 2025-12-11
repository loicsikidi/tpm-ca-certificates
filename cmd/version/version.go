package version

import (
	"fmt"

	goversion "github.com/caarlos0/go-version"
	"github.com/spf13/cobra"
)

// NewCommand creates the version command.
func NewCommand(info goversion.Info) *cobra.Command {
	cmd := &cobra.Command{
		Use:          "version",
		Short:        "display the current version of the cli",
		Long:         `Display detailed version information including revision, version, build time, and dirty status.`,
		SilenceUsage: true,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(info.String())
		},
	}

	return cmd
}
