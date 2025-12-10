package validate

import (
	"crypto/x509"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/fingerprint"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
)

func TestContainsCertificate(t *testing.T) {
	tests := []struct {
		name  string
		certs []config.Certificate
		cert  config.Certificate
		want  bool
	}{
		{
			name:  "empty list",
			certs: []config.Certificate{},
			cert: config.Certificate{
				Name: "Test Cert",
				URL:  "https://example.com/cert1.crt",
				Validation: config.Validation{
					Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "abc123"),
				},
			},
			want: false,
		},
		{
			name: "certificate found by name",
			certs: []config.Certificate{
				{
					Name: "Test Cert",
					URL:  "https://example.com/cert1.crt",
					Validation: config.Validation{
						Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "abc123"),
					},
				},
			},
			cert: config.Certificate{
				Name: "Test Cert",
				URL:  "https://example.com/cert2.crt",
				Validation: config.Validation{
					Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "def456"),
				},
			},
			want: true,
		},
		{
			name: "certificate found by URL",
			certs: []config.Certificate{
				{
					Name: "Cert A",
					URL:  "https://example.com/cert1.crt",
					Validation: config.Validation{
						Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "abc123"),
					},
				},
			},
			cert: config.Certificate{
				Name: "Cert B",
				URL:  "https://example.com/cert1.crt",
				Validation: config.Validation{
					Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "def456"),
				},
			},
			want: true,
		},
		{
			name: "certificate found by fingerprint",
			certs: []config.Certificate{
				{
					Name: "Cert A",
					URL:  "https://example.com/cert1.crt",
					Validation: config.Validation{
						Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "abc123"),
					},
				},
			},
			cert: config.Certificate{
				Name: "Cert B",
				URL:  "https://example.com/cert2.crt",
				Validation: config.Validation{
					Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "abc123"),
				},
			},
			want: true,
		},
		{
			name: "certificate not found",
			certs: []config.Certificate{
				{
					Name: "Cert A",
					URL:  "https://example.com/cert1.crt",
					Validation: config.Validation{
						Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "abc123"),
					},
				},
			},
			cert: config.Certificate{
				Name: "Cert B",
				URL:  "https://example.com/cert2.crt",
				Validation: config.Validation{
					Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "def456"),
				},
			},
			want: false,
		},
		{
			name: "multiple certificates, found in middle",
			certs: []config.Certificate{
				{
					Name: "Cert A",
					URL:  "https://example.com/cert1.crt",
					Validation: config.Validation{
						Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "abc123"),
					},
				},
				{
					Name: "Target Cert",
					URL:  "https://example.com/cert2.crt",
					Validation: config.Validation{
						Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "target"),
					},
				},
				{
					Name: "Cert C",
					URL:  "https://example.com/cert3.crt",
					Validation: config.Validation{
						Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "ghi789"),
					},
				},
			},
			cert: config.Certificate{
				Name: "Target Cert",
				URL:  "https://example.com/different.crt",
				Validation: config.Validation{
					Fingerprint: *config.NewFingerprint(fingerprint.SHA256, "different"),
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContainsCertificate(tt.certs, tt.cert)
			if got != tt.want {
				t.Errorf("ContainsCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckCertificate(t *testing.T) {
	cert, _ := testutil.GenerateTestCert(t)
	fp1SHA256 := fingerprint.New(cert.Raw, fingerprint.SHA256)

	tests := []struct {
		name      string
		certs     []config.Certificate
		url       string
		cert      *x509.Certificate
		wantError bool
	}{
		{
			name:      "no duplicate",
			certs:     []config.Certificate{},
			url:       "https://example.com/cert1.crt",
			cert:      cert,
			wantError: false,
		},
		{
			name: "duplicate URL",
			certs: []config.Certificate{
				{
					Name: "Existing Cert",
					URL:  "https://example.com/cert1.crt",
					Validation: config.Validation{
						Fingerprint: *config.NewFingerprint(fingerprint.SHA256, fp1SHA256),
					},
				},
			},
			url:       "https://example.com/cert1.crt",
			cert:      cert,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckCertificate(tt.certs, tt.url, tt.cert)

			if tt.wantError && err == nil {
				t.Errorf("CheckCertificate() expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("CheckCertificate() unexpected error = %v", err)
			}
		})
	}
}
