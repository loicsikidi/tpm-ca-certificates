package github

import (
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// Repo represents a GitHub repository.
type Repo struct {
	Owner string
	Name  string
}

func (r *Repo) CheckAndSetDefaults() error {
	if r.Owner == "" {
		return fmt.Errorf("invalid input: 'Owner' is required")
	}
	if r.Name == "" {
		return fmt.Errorf("invalid input: 'Name' is required")
	}
	return nil
}

func (r *Repo) String() string {
	return r.Owner + "/" + r.Name
}

// Attestation represents a GitHub attestation for an artifact.
//
// Attestations provide provenance information about how an artifact was built,
// including the workflow, commit, and other metadata.
type Attestation struct {
	// Bundle contains the Sigstore bundle with signature and certificate
	Bundle *bundle.Bundle `json:"bundle"`

	// BundleURL is the URL to fetch the bundle (if not embedded)
	BundleURL string `json:"bundle_url,omitempty"`
}

// AttestationsResponse represents the response from GitHub attestations API.
//
// See: https://docs.github.com/en/rest/orgs/orgs#list-attestations
type AttestationsResponse struct {
	Attestations []*Attestation `json:"attestations"`
}

// Release represents a GitHub release.
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
}

// Asset represents a release asset.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// SortOrder defines the sort order for releases.
type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

// ReleasesOptions configures options for listing releases.
type ReleasesOptions struct {
	// PageSize specifies the number of releases to fetch per page (default: 10, max: 100)
	PageSize int

	// SortOrder specifies the sort order (default: desc - most recent first)
	SortOrder SortOrder

	// ReturnFirstValue indicates whether to return only the first value
	ReturnFirstValue bool
}

// CheckAndSetDefaults validates and sets default values for ReleasesOptions.
func (o *ReleasesOptions) CheckAndSetDefaults() error {
	if o.PageSize <= 0 {
		o.PageSize = 10
	}
	if o.PageSize > 100 {
		o.PageSize = 100
	}
	if o.SortOrder == "" {
		o.SortOrder = SortOrderDesc
	}
	if o.SortOrder != SortOrderAsc && o.SortOrder != SortOrderDesc {
		o.SortOrder = SortOrderDesc
	}
	return nil
}

// Client defines the interface for fetching attestations from GitHub.
//
// This interface allows for easy testing by mocking the GitHub API.
type Client interface {
	// GetAttestations fetches attestations for a given artifact digest.
	//
	// The digest should be in the format "sha256:HASH".
	// Owner and repo identify the GitHub repository (e.g., "owner/repo").
	GetAttestations(owner, repo, digest string) ([]*Attestation, error)
}
