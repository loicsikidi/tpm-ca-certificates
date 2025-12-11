package main

import (
	"os"

	goversion "github.com/caarlos0/go-version"
	"github.com/loicsikidi/tpm-ca-certificates/cmd/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/cmd/config"
	versionCmd "github.com/loicsikidi/tpm-ca-certificates/cmd/version"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cli"
	"github.com/spf13/cobra"
)

const website = "https://github.com/loicsikidi/tpm-ca-certificates"

var (
	version = ""
	builtBy = ""
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "tpmtb",
		Short: "TPM Trust Bundle",
		Long: `tpmtb (TPM Trust Bundle) manages TPM root certificate bundles.

The tool bundles TPM root certificates from various vendors
into a single PEM-encoded trust bundle. In addition, each published
bundle is supply-chain signed for integrity and authenticity verification.

Notes:
  * Generation is based on a YAML configuration file.
  * Verification is based on a public transparency log (ie. Rekor).
    * Github Attestations are supported as a verification source (ie. build provenance).
    * A checksum of each release artifact is signed using Sigstore (ie. integrity).
`,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(bundle.NewCommand())
	rootCmd.AddCommand(versionCmd.NewCommand(buildVersion(version, builtBy)))
	rootCmd.AddCommand(config.NewCommand())

	if err := rootCmd.Execute(); err != nil {
		cli.DisplayError("Error: %v\n", err)
		os.Exit(1)
	}
}

func buildVersion(version, builtBy string) goversion.Info {
	return goversion.GetVersionInfo(
		goversion.WithAppDetails("tpmtb", "TPM root of trust, simplified.", website),
		func(i *goversion.Info) {
			if version != "" {
				i.GitVersion = version
			}
			if builtBy != "" {
				i.BuiltBy = builtBy
			}
		},
	)
}
