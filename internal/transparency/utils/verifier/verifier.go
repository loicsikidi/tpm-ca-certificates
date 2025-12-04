package verifier

import (
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

var (
	defaultOptions = []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1), // Require valid SCT (Signed Certificate Timestamp)
		verify.WithTransparencyLog(1),             // Require transparency log entry
		verify.WithObserverTimestamps(1),          // Use observer timestamps from Rekor
	}
)

type Config struct {
	Root    root.TrustedMaterial
	Options []verify.VerifierOption
}

func (c *Config) CheckAndSetDefaults() error {
	if c.Root == nil {
		root, err := root.FetchTrustedRoot()
		if err != nil {
			return fmt.Errorf("failed to fetch trusted root: %w", err)
		}
		c.Root = root
	}
	if len(c.Options) == 0 {
		c.Options = defaultOptions
	}
	return nil
}

func New(cfg Config) (*verify.Verifier, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return verify.NewVerifier(cfg.Root, cfg.Options...)
}
