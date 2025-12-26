package download

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/utils"
)

// Client handles HTTPS certificate downloads.
type Client struct {
	HTTPClient utils.HttpClient
}

var defaultClient = &http.Client{
	Timeout: 5 * time.Second,
}

// NewClient creates a new download client with sensible defaults.
func NewClient(optionalClient ...utils.HttpClient) *Client {
	client := utils.OptionalArgWithDefault[utils.HttpClient](optionalClient, defaultClient)
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
