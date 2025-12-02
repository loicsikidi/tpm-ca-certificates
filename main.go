package main

import (
	"fmt"
	"os"

	"github.com/loicsikidi/tpm-ca-certificates/cmd/config"
	"github.com/loicsikidi/tpm-ca-certificates/cmd/generate"
	"github.com/loicsikidi/tpm-ca-certificates/cmd/verify"
	"github.com/loicsikidi/tpm-ca-certificates/cmd/version"
	"github.com/spf13/cobra"
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

	rootCmd.AddCommand(generate.NewCommand())
	rootCmd.AddCommand(version.NewCommand())
	rootCmd.AddCommand(config.NewCommand())
	rootCmd.AddCommand(verify.NewCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
