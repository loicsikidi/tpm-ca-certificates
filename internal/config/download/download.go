package download

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config/download/source"
	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

// Client handles HTTPS certificate downloads.
type Client struct {
	HTTPClient utils.HTTPClient
}

var defaultClient = &http.Client{
	Timeout: 5 * time.Second,
}

// NewClient creates a new download client with sensible defaults.
func NewClient(optionalClient ...utils.HTTPClient) *Client {
	client := utils.OptionalArgWithDefault[utils.HTTPClient](optionalClient, defaultClient)
	return &Client{
		HTTPClient: client,
	}
}

// DownloadCertificate downloads a certificate from the given HTTPS URL.
//
// It returns the raw certificate bytes (typically DER-encoded).
// The method fails if the URL is not HTTPS or if the download fails.
//
// Example:
//
//	client := download.NewClient()
//	certBytes, err := client.DownloadCertificate(ctx, "https://example.com/cert.cer")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// Deprecated: Use [FetchCertificate] instead.
func (c *Client) DownloadCertificate(ctx context.Context, url string) (*x509.Certificate, error) {
	data, err := utils.HttpGET(ctx, c.HTTPClient, url)
	if err != nil {
		return nil, fmt.Errorf("failed to download certificate from %s: %w", url, err)
	}

	cert, err := ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from %s: %w", url, err)
	}

	return cert, nil
}

// FetchCertificate retrieves a certificate from a URI (supports https:// and file:// schemes).
//
// Example:
//
//	client := download.NewClient()
//	cert, err := client.FetchCertificate(ctx, "file:///home/user/repo/certs/root.pem")
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *Client) FetchCertificate(ctx context.Context, uri string) (*x509.Certificate, error) {
	resolver, err := source.NewResolver(uri, c.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create resolver for %s: %w", uri, err)
	}

	data, err := resolver.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate from %s: %w", uri, err)
	}

	cert, err := ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from %s: %w", uri, err)
	}

	return cert, nil
}

// ParseCertificate attempts to parse a certificate from DER or PEM format.
func ParseCertificate(data []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		return cert, nil
	}

	// fallback to PEM decoding
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block and DER parsing also failed")
	}
	return x509.ParseCertificate(block.Bytes)
}
