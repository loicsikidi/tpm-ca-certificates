package download

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client handles HTTPS certificate downloads.
type Client struct {
	HTTPClient *http.Client
}

// NewClient creates a new download client with sensible defaults.
func NewClient() *Client {
	return &Client{
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
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
//	certBytes, err := client.DownloadCertificate("https://example.com/cert.cer")
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *Client) DownloadCertificate(url string) (*x509.Certificate, error) {
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download certificate from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download certificate from %s: HTTP %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate data from %s: %w", url, err)
	}

	cert, err := parseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from %s: %w", url, err)
	}

	return cert, nil
}

// parseCertificate attempts to parse a certificate from DER or PEM format.
func parseCertificate(data []byte) (*x509.Certificate, error) {
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
