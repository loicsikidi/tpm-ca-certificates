package verifier

import (
	"fmt"
	"path/filepath"

	"github.com/cenkalti/backoff/v5"
	"github.com/loicsikidi/tpm-ca-certificates/internal/cache"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

const rootTarget = "trusted_root.json"

var (
	defaultOptions = []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1), // Require valid SCT (Signed Certificate Timestamp)
		verify.WithTransparencyLog(1),             // Require transparency log entry
		verify.WithObserverTimestamps(1),          // Use observer timestamps from Rekor
	}
)

type Config struct {
	Root       root.TrustedMaterial
	HTTPClient utils.HTTPClient
	Options    []verify.VerifierOption
}

func (c *Config) CheckAndSetDefaults() error {
	if c.Root == nil {
		root, err := root.FetchTrustedRootWithOptions(GetDefaultTUFOptions(c.HTTPClient))
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

// GetDefaultTUFOptions returns TUF options with sane defaults for Sigstore usage.
func GetDefaultTUFOptions(optionalClient ...utils.HTTPClient) *tuf.Options {
	client := utils.OptionalArg(optionalClient)
	opts := tuf.DefaultOptions()

	// Store TUF cache in a directory owned by tpmtb for better isolation
	opts.CachePath = filepath.Join(cache.CacheDir(), ".sigstore", "root")

	// Allow TUF cache for 1 day
	opts.CacheValidity = 1

	// configure fetcher with retry logic
	f := fetcher.NewDefaultFetcher()
	if client != nil {
		f.SetHTTPClient(client)
	}
	retryOptions := []backoff.RetryOption{backoff.WithMaxTries(3)}
	f.SetRetryOptions(retryOptions...)
	opts.WithFetcher(f)

	return opts
}

// FetchTrustedRoot fetches the Sigstore trusted_root.json from TUF and returns it as a compact JSON buffer.
//
// This is useful for offline verification scenarios where the trusted root needs to be cached locally.
//
// Example:
//
//	trustedRootJSON, err := verifier.FetchTrustedRoot()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	os.WriteFile("trusted-root.json", trustedRootJSON, 0644)
func FetchTrustedRoot(optionalClient ...utils.HTTPClient) ([]byte, error) {
	client := utils.OptionalArg(optionalClient)
	opts := GetDefaultTUFOptions(client)
	opts.DisableLocalCache = true

	tufClient, err := tuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUF client: %w", err)
	}

	target, err := tufClient.GetTarget(rootTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve trusted_root.json via TUF: %w", err)
	}

	output, err := utils.JsonCompact(target)
	if err != nil {
		return nil, err
	}

	return output, nil
}
