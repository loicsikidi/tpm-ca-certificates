package verifier

import (
	"crypto/x509"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/root"
)

const (
	// PublicGoodIssuerOrg is the expected organization for Sigstore public good certificates.
	PublicGoodIssuerOrg = "sigstore.dev"
)

// LoadTrustedRoot loads and validates a Sigstore trusted root from JSON.
//
// The function ensures that all Fulcio certificate authorities in the trusted root
// are issued by the Sigstore public good organization to prevent the use of
// untrusted or malicious certificate authorities.
//
// Returns an error if:
//   - The JSON is invalid or cannot be parsed
//   - Any certificate authority is not issued by sigstore.dev
//   - The trusted root structure is invalid
func LoadTrustedRoot(rootJSON []byte) (*root.TrustedRoot, error) {
	trustedRoot, err := root.NewTrustedRootFromJSON(rootJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trusted root JSON: %w", err)
	}

	// Validate that all certificate authorities are from the public good instance
	certAuthorities := trustedRoot.FulcioCertificateAuthorities()
	for _, certAuthority := range certAuthorities {
		fulcioCertAuthority, ok := certAuthority.(*root.FulcioCertificateAuthority)
		if !ok {
			return nil, fmt.Errorf("trusted root cert authority is not a FulcioCertificateAuthority")
		}

		lowestCert, err := getLowestCertInChain(fulcioCertAuthority)
		if err != nil {
			return nil, err
		}

		if len(lowestCert.Issuer.Organization) == 0 {
			return nil, fmt.Errorf("certificate authority has no issuer organization")
		}

		issuer := lowestCert.Issuer.Organization[0]
		if issuer != PublicGoodIssuerOrg {
			return nil, fmt.Errorf("untrusted issuer organization: %s (expected %s)", issuer, PublicGoodIssuerOrg)
		}
	}

	return trustedRoot, nil
}

// getLowestCertInChain returns the lowest certificate in the authority's chain.
// This is typically the intermediate certificate if available, otherwise the root.
func getLowestCertInChain(ca *root.FulcioCertificateAuthority) (*x509.Certificate, error) {
	if len(ca.Intermediates) > 0 {
		return ca.Intermediates[0], nil
	} else if ca.Root != nil {
		return ca.Root, nil
	}

	return nil, fmt.Errorf("certificate authority had no certificates")
}
