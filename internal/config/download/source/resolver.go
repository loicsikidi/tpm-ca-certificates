package source

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/loicsikidi/go-utils/net/httputil"
	"github.com/loicsikidi/go-utils/system/fsutil"

	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

var defaultClient = &http.Client{
	Timeout: 5 * time.Second,
}

// Resolver retrieves certificate data from various sources (HTTPS or filesystem).
type Resolver interface {
	// Fetch retrieves the raw certificate data.
	Fetch(ctx context.Context) ([]byte, error)
}

// HTTPSResolver downloads certificates from HTTPS URLs.
type HTTPSResolver struct {
	url               string
	httpClient        utils.HTTPClient
	allowHttpFallback bool
}

// NewHTTPSResolver creates a new HTTPS resolver.
func NewHTTPSResolver(url string, httpClient utils.HTTPClient, allowHttpFallback bool) *HTTPSResolver {
	return &HTTPSResolver{
		url:               url,
		httpClient:        httpClient,
		allowHttpFallback: allowHttpFallback,
	}
}

// Fetch downloads the certificate from the HTTPS URL.
// If HTTPS fails and allowHttpFallback is true, attempts HTTP as fallback.
func (r *HTTPSResolver) Fetch(ctx context.Context) ([]byte, error) {
	data, err := httputil.HttpGET(ctx, r.httpClient, r.url)
	if err != nil {
		if r.allowHttpFallback {
			httpURL := strings.Replace(r.url, "https://", "http://", 1)
			data, httpErr := httputil.HttpGET(ctx, r.httpClient, httpURL)
			if httpErr != nil {
				return nil, fmt.Errorf("failed to download from %s (HTTPS error: %w) and HTTP fallback from %s failed: %v", r.url, err, httpURL, httpErr)
			}
			return data, nil
		}
		return nil, fmt.Errorf("failed to download from %s: %w", r.url, err)
	}
	return data, nil
}

// FileResolver reads certificates from the local filesystem.
type FileResolver struct {
	path string // path MUST be absolute
}

// NewFileResolver creates a new file resolver.
func NewFileResolver(path string) (*FileResolver, error) {
	absPath := strings.TrimPrefix(path, "file://")

	if !filepath.IsAbs(absPath) {
		return nil, fmt.Errorf("relative paths are not supported")
	}
	return &FileResolver{
		path: absPath,
	}, nil
}

// Fetch reads the certificate from the filesystem.
func (r *FileResolver) Fetch(ctx context.Context) ([]byte, error) {
	data, err := fsutil.ReadFile(r.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", r.path, err)
	}
	return data, nil
}

type Config struct {
	URI               string
	HttpClient        utils.HTTPClient
	AllowHttpFallback bool
}

func (c *Config) CheckAndSetDefaults() error {
	if c.HttpClient == nil {
		c.HttpClient = defaultClient
	}
	if c.URI == "" {
		return fmt.Errorf("uri must be provided")
	}
	return nil
}

// NewResolver creates the appropriate resolver based on the URI scheme.
//
// Supported schemes:
//   - https:// - Uses [HTTPSResolver]
//   - file:// - Uses [FileResolver]
//
// Example:
//
//	// HTTPS resolver
//	resolver, err := NewResolver(Config{URI: "https://example.com/cert.cer"})
//
//	// File resolver (absolute)
//	resolver, err := NewResolver(Config{URI: "file:///home/user/repo/certs/root.pem"})
func NewResolver(config Config) (Resolver, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, err
	}

	parsedURI, err := url.Parse(config.URI)
	if err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	switch parsedURI.Scheme {
	case "https":
		return NewHTTPSResolver(config.URI, config.HttpClient, config.AllowHttpFallback), nil
	case "file":
		return NewFileResolver(config.URI)
	default:
		return nil, fmt.Errorf("unsupported URI scheme '%s': must be 'https' or 'file'", parsedURI.Scheme)
	}
}
