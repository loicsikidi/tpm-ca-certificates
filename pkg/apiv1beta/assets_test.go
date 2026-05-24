package apiv1beta

import (
	"encoding/json"
	"testing"

	"github.com/loicsikidi/go-utils/system/fsutil"
	"github.com/loicsikidi/tpm-ca-certificates/internal/github"
	sigstoreBundle "github.com/sigstore/sigstore-go/pkg/bundle"
)

func TestIsProvenanceAttestation(t *testing.T) {
	tests := []struct {
		name            string
		makeAttestation func(t *testing.T) *github.Attestation
		wantProvenance  bool
	}{
		{
			name: "SLSA provenance attestation",
			makeAttestation: func(t *testing.T) *github.Attestation {
				return loadAttestationFromFile(t, "testdata/provenance.json")
			},
			wantProvenance: true,
		},
		{
			name: "release attestation",
			makeAttestation: func(t *testing.T) *github.Attestation {
				return loadAttestationFromFile(t, "testdata/immutable.release.json")
			},
			wantProvenance: false,
		},
		{
			name: "nil attestation",
			makeAttestation: func(t *testing.T) *github.Attestation {
				return nil
			},
			wantProvenance: false,
		},
		{
			name: "empty bundle",
			makeAttestation: func(t *testing.T) *github.Attestation {
				return &github.Attestation{}
			},
			wantProvenance: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation := tt.makeAttestation(t)
			got := isProvenanceAttestation(attestation)
			if got != tt.wantProvenance {
				t.Errorf("isProvenanceAttestation() = %v, want %v", got, tt.wantProvenance)
			}
		})
	}
}

func loadAttestationFromFile(t *testing.T, path string) *github.Attestation {
	t.Helper()

	bundleData, err := fsutil.ReadFile(path)
	if err != nil {
		t.Skipf("test file not found: %v", err)
	}

	var bundle sigstoreBundle.Bundle
	if err := json.Unmarshal(bundleData, &bundle); err != nil {
		t.Fatalf("failed to unmarshal bundle: %v", err)
	}

	return &github.Attestation{
		Bundle: &bundle,
	}
}
