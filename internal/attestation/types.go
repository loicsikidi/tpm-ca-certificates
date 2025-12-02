package attestation

import "github.com/sigstore/sigstore-go/pkg/bundle"

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
