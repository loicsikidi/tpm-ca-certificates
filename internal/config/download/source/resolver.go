package source

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

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
	url        string
	httpClient utils.HTTPClient
}

// NewHTTPSResolver creates a new HTTPS resolver.
func NewHTTPSResolver(url string, httpClient utils.HTTPClient) *HTTPSResolver {
	return &HTTPSResolver{
		url:        url,
		httpClient: httpClient,
	}
}

// Fetch downloads the certificate from the HTTPS URL.
func (r *HTTPSResolver) Fetch(ctx context.Context) ([]byte, error) {
	data, err := utils.HttpGET(ctx, r.httpClient, r.url)
	if err != nil {
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
	data, err := utils.ReadFile(r.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", r.path, err)
	}
	return data, nil
}

// NewResolver creates the appropriate resolver based on the URI scheme.
//
// Supported schemes:
//   - https:// - Uses [HTTPSResolver]
//   - file:// - Uses [FileResolver]
//
// The repoRoot parameter is used to resolve relative file:// paths.
//
// Example:
//
//	// HTTPS resolver
//	resolver, err := NewResolver("https://example.com/cert.cer", httpClient)
//
//	// File resolver (absolute)
//	resolver, err := NewResolver("file:///home/user/repo/certs/root.pem")
func NewResolver(uri string, optionalHttpClient ...utils.HTTPClient) (Resolver, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	switch parsedURI.Scheme {
	case "https":
		httpClient := utils.OptionalArgWithDefault[utils.HTTPClient](optionalHttpClient, defaultClient)
		return NewHTTPSResolver(uri, httpClient), nil
	case "file":
		return NewFileResolver(uri)
	default:
		return nil, fmt.Errorf("unsupported URI scheme '%s': must be 'https' or 'file'", parsedURI.Scheme)
	}
}
