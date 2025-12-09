package certificates

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
)

func TestCertificateExists(t *testing.T) {
	// Helper to create a dummy x509 certificate with specific raw data
	createDummyCert := func(rawData []byte) *x509.Certificate {
		return &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "Test Certificate",
			},
			Raw: rawData,
		}
	}

	// Sample raw certificate data for testing
	rawCert1 := []byte("test-cert-data-1")
	rawCert2 := []byte("test-cert-data-2")

	// Calculate fingerprints for test data
	fp1SHA256 := CalculateFingerprint(rawCert1, sha256)
	fp2SHA256 := CalculateFingerprint(rawCert2, sha256)
	fp1SHA512 := CalculateFingerprint(rawCert1, sha512)

	tests := []struct {
		name      string
		certs     []config.Certificate
		result    certDownloadResult
		hashAlgo  string
		wantError bool
		errMsg    string
	}{
		{
			name:  "no existing certificates",
			certs: []config.Certificate{},
			result: certDownloadResult{
				url:         "https://example.com/cert1.crt",
				cert:        createDummyCert(rawCert1),
				fingerprint: fp1SHA256,
			},
			hashAlgo:  sha256,
			wantError: false,
		},
		{
			name: "duplicate URL",
			certs: []config.Certificate{
				{
					Name: "Existing Cert",
					URL:  "https://example.com/cert1.crt",
					Validation: config.Validation{
						Fingerprint: config.Fingerprint{
							SHA256: fp2SHA256,
						},
					},
				},
			},
			result: certDownloadResult{
				url:         "https://example.com/cert1.crt",
				cert:        createDummyCert(rawCert1),
				fingerprint: fp1SHA256,
			},
			hashAlgo:  sha256,
			wantError: true,
			errMsg:    "duplicate URL",
		},
		{
			name: "duplicate fingerprint - same hash algorithm",
			certs: []config.Certificate{
				{
					Name: "Existing Cert",
					URL:  "https://example.com/cert-different.crt",
					Validation: config.Validation{
						Fingerprint: config.Fingerprint{
							SHA256: fp1SHA256,
						},
					},
				},
			},
			result: certDownloadResult{
				url:         "https://example.com/cert1.crt",
				cert:        createDummyCert(rawCert1),
				fingerprint: fp1SHA256,
			},
			hashAlgo:  sha256,
			wantError: true,
			errMsg:    "duplicate fingerprint",
		},
		{
			name: "duplicate fingerprint - different hash algorithm (SHA512 vs SHA256)",
			certs: []config.Certificate{
				{
					Name: "Existing Cert",
					URL:  "https://example.com/cert-different.crt",
					Validation: config.Validation{
						Fingerprint: config.Fingerprint{
							SHA512: fp1SHA512,
						},
					},
				},
			},
			result: certDownloadResult{
				url:         "https://example.com/cert1.crt",
				cert:        createDummyCert(rawCert1),
				fingerprint: fp1SHA256,
			},
			hashAlgo:  sha256,
			wantError: true,
			errMsg:    "duplicate fingerprint",
		},
		{
			name: "different URL and fingerprint",
			certs: []config.Certificate{
				{
					Name: "Existing Cert",
					URL:  "https://example.com/cert-different.crt",
					Validation: config.Validation{
						Fingerprint: config.Fingerprint{
							SHA256: fp2SHA256,
						},
					},
				},
			},
			result: certDownloadResult{
				url:         "https://example.com/cert1.crt",
				cert:        createDummyCert(rawCert1),
				fingerprint: fp1SHA256,
			},
			hashAlgo:  sha256,
			wantError: false,
		},
		{
			name: "multiple existing certificates - no duplicates",
			certs: []config.Certificate{
				{
					Name: "Cert A",
					URL:  "https://example.com/cert-a.crt",
					Validation: config.Validation{
						Fingerprint: config.Fingerprint{
							SHA256: fp2SHA256,
						},
					},
				},
				{
					Name: "Cert B",
					URL:  "https://example.com/cert-b.crt",
					Validation: config.Validation{
						Fingerprint: config.Fingerprint{
							SHA256: CalculateFingerprint([]byte("another-cert"), sha256),
						},
					},
				},
			},
			result: certDownloadResult{
				url:         "https://example.com/cert1.crt",
				cert:        createDummyCert(rawCert1),
				fingerprint: fp1SHA256,
			},
			hashAlgo:  sha256,
			wantError: false,
		},
		{
			name: "fingerprint case insensitive match",
			certs: []config.Certificate{
				{
					Name: "Existing Cert",
					URL:  "https://example.com/cert-different.crt",
					Validation: config.Validation{
						Fingerprint: config.Fingerprint{
							SHA256: fp1SHA256,
						},
					},
				},
			},
			result: certDownloadResult{
				url:         "https://example.com/cert1.crt",
				cert:        createDummyCert(rawCert1),
				fingerprint: fp1SHA256,
			},
			hashAlgo:  sha256,
			wantError: true,
			errMsg:    "duplicate fingerprint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := certificateExists(tt.certs, tt.result, tt.hashAlgo)

			if tt.wantError {
				if err == nil {
					t.Errorf("certificateExists() expected error but got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("certificateExists() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("certificateExists() unexpected error = %v", err)
				}
			}
		})
	}
}
