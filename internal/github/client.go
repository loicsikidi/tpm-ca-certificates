package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

var SourceRepo = Repo{Owner: "loicsikidi", Name: "tpm-ca-certificates"}

const (
	ReleaseBundleWorkflowPath = ".github/workflows/release-bundle.yaml"
	githubAPIBaseURL          = "https://apiv1beta.github.com"
	apiVersion                = "2022-11-28"
)

// httpClient defines the minimal interface for an HTTP client.
// This allows for easier testing and mocking.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPClient wraps the standard http.Client to implement attestation fetching.
//
// This client makes direct calls to the GitHub REST API without requiring
// the gh CLI or authentication for public repositories.
type HTTPClient struct {
	client httpClient
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
func (c *HTTPClient) GetAttestations(ctx context.Context, repo Repo, digest string) ([]*Attestation, error) {
	// Build API URL
	// Endpoint: GET /repos/{owner}/{repo}/attestations/{digest}
	url := fmt.Sprintf("%s/repos/%s/attestations/%s", githubAPIBaseURL, repo.String(), digest)

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

// GetReleases fetches releases with context support.
//
// Only releases with tags matching the YYYY-MM-DD format are returned.
// The opts parameter allows customization of page size and sort order.
//
// Example:
//
//	client := NewHTTPClient(nil)
//	opts := ReleasesOptions{PageSize: 20, SortOrder: SortOrderDesc}
//	releases, err := client.GetReleases("loicsikidi", "tpm-ca-certificates", opts)
func (c *HTTPClient) GetReleases(ctx context.Context, repo Repo, opts ReleasesOptions) ([]Release, error) {
	if err := opts.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	// Build API URL
	// Endpoint: GET /repos/{owner}/{repo}/releases
	url := fmt.Sprintf("%s/repos/%s/releases?per_page=%d", githubAPIBaseURL, repo.String(), opts.PageSize)

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
		return nil, fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var releases []Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Filter releases to only include YYYY-MM-DD format tags
	var bundleReleases []Release
	for _, release := range releases {
		if isDateTag(release.TagName) {
			bundleReleases = append(bundleReleases, release)
		}
	}

	// Sort releases based on sort order
	if opts.SortOrder == SortOrderAsc {
		// Reverse the slice for ascending order (GitHub API returns desc by default)
		slices.Reverse(bundleReleases)
	}

	if opts.ReturnFirstValue && len(bundleReleases) > 0 {
		return bundleReleases[:1], nil
	}

	return bundleReleases, nil
}

// ReleaseExists checks if a release with the given tag exists.
//
// Example:
//
//	client := NewHTTPClient(nil)
//	err := client.ReleaseExists(ctx, repo, "2025-12-03")
//	if err != nil {
//	    // Release doesn't exist
//	}
func (c *HTTPClient) ReleaseExists(ctx context.Context, repo Repo, tag string) error {
	url := fmt.Sprintf("%s/repos/%s/releases/tags/%s", githubAPIBaseURL, repo.String(), tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("release not found")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// DownloadAsset downloads a release asset to the specified destination.
//
// The asset is identified by its name within a specific release tag.
// The destination should be a file path where the asset will be saved.
//
// Example:
//
//	client := NewHTTPClient(nil)
//	err := client.DownloadAsset(ctx, repo, "2025-12-03", "tpm-ca-certificates.pem", "/tmp/bundle.pem")
func (c *HTTPClient) DownloadAssetToFile(ctx context.Context, repo Repo, tag, assetName, destination string) error {
	data, err := c.DownloadAsset(ctx, repo, tag, assetName)
	if err != nil {
		return err
	}

	// Write to destination file
	if err := os.WriteFile(destination, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// DownloadAsset downloads a release asset to memory.
//
// The asset is identified by its name within a specific release tag.
// Returns the asset content as a byte slice.
//
// Example:
//
//	client := NewHTTPClient(nil)
//	data, err := client.DownloadAsset(ctx, repo, "2025-12-03", "tpm-ca-certificates.pem")
func (c *HTTPClient) DownloadAsset(ctx context.Context, repo Repo, tag, assetName string) ([]byte, error) {
	// First, fetch the release to get the asset URL
	url := fmt.Sprintf("%s/repos/%s/releases/tags/%s", githubAPIBaseURL, repo.String(), tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to decode release: %w", err)
	}

	var assetURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			assetURL = asset.BrowserDownloadURL
			break
		}
	}

	if assetURL == "" {
		return nil, fmt.Errorf("asset %q not found in release %q", assetName, tag)
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}

	resp, err = c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return data, nil
}

var dateTagRegex = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// isDateTag checks if a tag name matches the YYYY-MM-DD format.
func isDateTag(tag string) bool {
	return dateTagRegex.MatchString(tag)
}
