package bundle_test

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	bundlepkg "github.com/loicsikidi/tpm-ca-certificates/internal/bundle"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
)

func TestGenerate(t *testing.T) {
	certDER, fingerprint := testutil.GenerateTestCertDER(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(certDER)
	}))
	defer server.Close()

	fpFormatted := formatFingerprintWithColons(fingerprint)

	cfg := &config.TPMRootsConfig{
		Version: "alpha",
		Vendors: []config.Vendor{
			{
				Name: "Test Vendor",
				ID:   "TV",
				Certificates: []config.Certificate{
					{
						Name: "Test Cert",
						URL:  server.URL,
						Validation: config.Validation{
							Fingerprint: config.Fingerprint{
								SHA1: fpFormatted,
							},
						},
					},
				},
			},
		},
	}

	t.Run("successful generation", func(t *testing.T) {
		gen := bundlepkg.NewGenerator(server.Client())

		bundle, err := gen.Generate(cfg)
		if err != nil {
			t.Fatalf("Generate() error = %v", err)
		}

		if !strings.Contains(bundle, "BEGIN CERTIFICATE") {
			t.Error("Generated bundle does not contain PEM header")
		}

		if !strings.Contains(bundle, "END CERTIFICATE") {
			t.Error("Generated bundle does not contain PEM footer")
		}
	})
}

func TestEncodePEM(t *testing.T) {
	certDER, _ := testutil.GenerateTestCertDER(t)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	pemStr := string(bundle.EncodePEM(cert))

	if !strings.Contains(pemStr, "BEGIN CERTIFICATE") {
		t.Error("encodePEM() does not contain BEGIN CERTIFICATE")
	}

	if !strings.Contains(pemStr, "END CERTIFICATE") {
		t.Error("encodePEM() does not contain END CERTIFICATE")
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM block type = %v, want CERTIFICATE", block.Type)
	}
}

func formatFingerprintWithColons(hexStr string) string {
	var result string
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			result += ":"
		}
		result += hexStr[i : i+2]
	}
	return strings.ToUpper(result)
}
