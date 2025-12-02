package download

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
)

func TestDownloadCertificate(t *testing.T) {
	t.Run("successful download", func(t *testing.T) {
		testData, _ := testutil.GenerateTestCertDER(t)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(testData)
		}))
		defer server.Close()

		client := &Client{HTTPClient: server.Client()}
		_, err := client.DownloadCertificate(server.URL)
		if err != nil {
			t.Fatalf("DownloadCertificate() error = %v", err)
		}
	})

	t.Run("http 404", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		wantErr := "failed to download certificate from " + server.URL + ": HTTP 404"

		client := &Client{HTTPClient: server.Client()}
		_, err := client.DownloadCertificate(server.URL)
		if err == nil {
			t.Error("DownloadCertificate() expected error for 404")
		}
		if err.Error() != wantErr {
			t.Errorf("DownloadCertificate() unexpected error message: got=%s, want=%s", err, wantErr)
		}
	})

	t.Run("empty response", func(t *testing.T) {
		wantErr := "failed to decode PEM block and DER parsing also failed"
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := &Client{HTTPClient: server.Client()}
		_, err := client.DownloadCertificate(server.URL)
		if err == nil {
			t.Error("DownloadCertificate() expected error for empty response")
		}
		if !strings.Contains(err.Error(), wantErr) {
			t.Errorf("DownloadCertificate() unexpected error message: got=%s, want=%s", err, wantErr)
		}
	})

	t.Run("invalid url", func(t *testing.T) {
		wantErr := "failed to download certificate from"
		client := NewClient()
		_, err := client.DownloadCertificate("://invalid-url")
		if err == nil {
			t.Error("DownloadCertificate() expected error for invalid URL")
		}
		if !strings.HasPrefix(err.Error(), wantErr) {
			t.Errorf("DownloadCertificate() unexpected error message: got=%s, want=%s", err, wantErr)
		}
	})
}

func TestParseCertificate(t *testing.T) {
	certDER, _ := testutil.GenerateTestCertDER(t)

	t.Run("parse DER format", func(t *testing.T) {
		cert, err := parseCertificate(certDER)
		if err != nil {
			t.Fatalf("parseCertificate() error = %v", err)
		}
		if cert == nil {
			t.Error("parseCertificate() returned nil certificate")
		}
	})

	t.Run("parse PEM format", func(t *testing.T) {
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})

		cert, err := parseCertificate(pemBlock)
		if err != nil {
			t.Fatalf("parseCertificate() error = %v", err)
		}
		if cert == nil {
			t.Error("parseCertificate() returned nil certificate")
		}
	})

	t.Run("invalid data", func(t *testing.T) {
		_, err := parseCertificate([]byte("invalid data"))
		if err == nil {
			t.Error("parseCertificate() expected error for invalid data")
		}
	})
}
