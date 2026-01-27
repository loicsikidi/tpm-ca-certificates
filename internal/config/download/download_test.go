package download_test

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config/download"
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

		client := download.NewClient(server.Client())
		_, err := client.DownloadCertificate(t.Context(), server.URL)
		if err != nil {
			t.Fatalf("DownloadCertificate() error = %v", err)
		}
	})

	t.Run("http 404", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		client := download.NewClient(server.Client())
		_, err := client.DownloadCertificate(t.Context(), server.URL)
		if err == nil {
			t.Error("DownloadCertificate() expected error for 404")
		}
		if !strings.Contains(err.Error(), "failed to download certificate from "+server.URL) {
			t.Errorf("DownloadCertificate() unexpected error message: got=%s", err)
		}
		if !strings.Contains(err.Error(), "HTTP 404") {
			t.Errorf("DownloadCertificate() error should mention HTTP 404: got=%s", err)
		}
	})

	t.Run("empty response", func(t *testing.T) {
		wantErr := "failed to decode PEM block and DER parsing also failed"
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client := download.NewClient(server.Client())
		_, err := client.DownloadCertificate(t.Context(), server.URL)
		if err == nil {
			t.Error("DownloadCertificate() expected error for empty response")
		}
		if !strings.Contains(err.Error(), wantErr) {
			t.Errorf("DownloadCertificate() unexpected error message: got=%s, want=%s", err, wantErr)
		}
	})

	t.Run("invalid url", func(t *testing.T) {
		client := download.NewClient()
		_, err := client.DownloadCertificate(t.Context(), "://invalid-url")
		if err == nil {
			t.Error("DownloadCertificate() expected error for invalid URL")
		}
		if !strings.Contains(err.Error(), "failed to download certificate from ://invalid-url") {
			t.Errorf("DownloadCertificate() unexpected error message: got=%s", err)
		}
	})
}

func TestParseCertificate(t *testing.T) {
	certDER, _ := testutil.GenerateTestCertDER(t)

	t.Run("parse DER format", func(t *testing.T) {
		cert, err := download.ParseCertificate(certDER)
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

		cert, err := download.ParseCertificate(pemBlock)
		if err != nil {
			t.Fatalf("parseCertificate() error = %v", err)
		}
		if cert == nil {
			t.Error("parseCertificate() returned nil certificate")
		}
	})

	t.Run("invalid data", func(t *testing.T) {
		_, err := download.ParseCertificate([]byte("invalid data"))
		if err == nil {
			t.Error("parseCertificate() expected error for invalid data")
		}
	})
}

func TestFetchCertificate(t *testing.T) {
	t.Run("fetch from HTTPS URI", func(t *testing.T) {
		testData, _ := testutil.GenerateTestCertDER(t)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(testData)
		}))
		defer server.Close()

		client := download.NewClient(server.Client())
		_, err := client.FetchCertificate(t.Context(), server.URL)
		if err != nil {
			t.Fatalf("FetchCertificate() error = %v", err)
		}
	})

	t.Run("fetch from file:// URI with absolute path", func(t *testing.T) {
		tmpDir := t.TempDir()
		testData, _ := testutil.GenerateTestCertDER(t)

		// Create test certificate file
		certPath := filepath.Join(tmpDir, "cert.pem")
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: testData,
		})
		if err := os.WriteFile(certPath, pemBlock, 0644); err != nil {
			t.Fatal(err)
		}

		client := download.NewClient()
		uri := "file://" + certPath
		_, err := client.FetchCertificate(t.Context(), uri)
		if err != nil {
			t.Fatalf("FetchCertificate() error = %v", err)
		}
	})

	t.Run("returns error for unsupported scheme", func(t *testing.T) {
		client := download.NewClient()
		_, err := client.FetchCertificate(t.Context(), "ftp://example.com/cert.cer")
		if err == nil {
			t.Error("FetchCertificate() expected error for unsupported scheme")
		}
		if !strings.Contains(err.Error(), "unsupported URI scheme") {
			t.Errorf("FetchCertificate() unexpected error message: got=%s", err)
		}
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		client := download.NewClient()
		_, err := client.FetchCertificate(t.Context(), "file:///non/existent/cert.pem")
		if err == nil {
			t.Error("FetchCertificate() expected error for non-existent file")
		}
	})

	t.Run("returns error for invalid certificate data", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "invalid.pem")

		if err := os.WriteFile(certPath, []byte("invalid certificate data"), 0644); err != nil {
			t.Fatal(err)
		}

		client := download.NewClient()
		uri := "file://" + certPath
		_, err := client.FetchCertificate(t.Context(), uri)
		if err == nil {
			t.Error("FetchCertificate() expected error for invalid certificate")
		}
		if !strings.Contains(err.Error(), "failed to parse certificate") {
			t.Errorf("FetchCertificate() unexpected error message: got=%s", err)
		}
	})
}
