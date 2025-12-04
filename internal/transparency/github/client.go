package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

const (
	githubAPIBaseURL = "https://api.github.com"
	apiVersion       = "2022-11-28"
)

// HTTPClient wraps the standard http.Client to implement attestation fetching.
//
// This client makes direct calls to the GitHub REST API without requiring
// the gh CLI or authentication for public repositories.
type HTTPClient struct {
	client *http.Client
}

// NewHTTPClient creates a new GitHub attestation client.
//
// The client uses the provided http.Client for making requests.
// If nil is provided, http.DefaultClient is used.
func NewHTTPClient(httpClient *http.Client) *HTTPClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &HTTPClient{
		client: httpClient,
	}
}

// GetAttestations fetches attestations for a given artifact digest from GitHub.
//
// The digest must be in the format "sha256:HASH". The owner and repo parameters
// should be provided as separate strings (e.g., "loicsikidi" and "tpm-trust-bundle").
//
// This implementation uses a simple approach without full pagination support,
// as we expect a small number of attestations (typically < 5).
//
// Example:
//
//	client := NewHTTPClient(nil)
//	attestations, err := client.GetAttestations("loicsikidi", "tpm-trust-bundle", "sha256:abc123...")
//	if err != nil {
//	    return err
//	}
func (c *HTTPClient) GetAttestations(owner, repo, digest string) ([]*Attestation, error) {
	return c.GetAttestationsWithContext(context.Background(), owner, repo, digest)
}

// GetAttestationsWithContext fetches attestations with context support.
func (c *HTTPClient) GetAttestationsWithContext(ctx context.Context, owner, repo, digest string) ([]*Attestation, error) {
	// Build API URL
	// Endpoint: GET /repos/{owner}/{repo}/attestations/{digest}
	url := fmt.Sprintf("%s/repos/%s/%s/attestations/%s", githubAPIBaseURL, owner, repo, digest)

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set required headers
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)

	// Execute request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch attestations: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var attResp AttestationsResponse
	if err := json.NewDecoder(resp.Body).Decode(&attResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Process attestations - load bundles if they're provided via URL
	for i, att := range attResp.Attestations {
		if att.Bundle == nil && att.BundleURL != "" {
			loadedBundle, err := c.fetchBundle(ctx, att.BundleURL)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch bundle %d: %w", i, err)
			}
			att.Bundle = loadedBundle
		}
	}

	return attResp.Attestations, nil
}

// fetchBundle downloads and parses a bundle from a URL.
//
// GitHub stores bundles as snappy-compressed protobuf JSON at bundle_url.
// However, for inline bundles in the API response, no decompression is needed.
func (c *HTTPClient) fetchBundle(ctx context.Context, bundleURL string) (*bundle.Bundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bundleURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create bundle request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle URL returned status %d", resp.StatusCode)
	}

	// Read bundle content
	bundleBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle: %w", err)
	}

	// Try to parse as JSON bundle directly
	// Note: GitHub may serve bundles compressed or uncompressed depending on the endpoint
	var loadedBundle bundle.Bundle
	if err := loadedBundle.UnmarshalJSON(bundleBytes); err != nil {
		// If JSON parsing fails, it might be compressed - but for now we'll return the error
		// as GitHub typically serves bundles uncompressed in API responses
		return nil, fmt.Errorf("failed to parse bundle: %w", err)
	}

	return &loadedBundle, nil
}
