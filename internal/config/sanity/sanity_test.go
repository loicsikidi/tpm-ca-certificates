package sanity

import (
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"github.com/loicsikidi/tpm-ca-certificates/internal/config/download"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
)

func TestChecker_Check(t *testing.T) {
	t.Run("valid certificates", func(t *testing.T) {
		certDER, fingerprint := testutil.GenerateTestCertDER(t)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(certDER)
		}))
		defer server.Close()

		cfg := &config.TPMRootsConfig{
			Version: "test",
			Vendors: []config.Vendor{
				{
					ID:   "TEST",
					Name: "Test Vendor",
					Certificates: []config.Certificate{
						{
							Name: "Test Cert",
							URL:  server.URL,
							Validation: config.Validation{
								Fingerprint: config.Fingerprint{
									SHA1: formatFingerprintWithColons(fingerprint),
								},
							},
						},
					},
				},
			},
		}

		checker := &Checker{
			downloader: &download.Client{HTTPClient: server.Client()},
		}

		result, err := checker.Check(cfg, 1, 90)
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}

		if result.HasIssues() {
			t.Errorf("Check() expected no issues, got validation errors: %d, expiration warnings: %d",
				len(result.ValidationErrors), len(result.ExpirationWarnings))
		}
	})

	t.Run("fingerprint mismatch", func(t *testing.T) {
		certDER, _ := testutil.GenerateTestCertDER(t)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(certDER)
		}))
		defer server.Close()

		cfg := &config.TPMRootsConfig{
			Version: "test",
			Vendors: []config.Vendor{
				{
					ID:   "TEST",
					Name: "Test Vendor",
					Certificates: []config.Certificate{
						{
							Name: "Test Cert",
							URL:  server.URL,
							Validation: config.Validation{
								Fingerprint: config.Fingerprint{
									SHA1: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
								},
							},
						},
					},
				},
			},
		}

		checker := &Checker{
			downloader: &download.Client{HTTPClient: server.Client()},
		}

		result, err := checker.Check(cfg, 1, 90)
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}

		if len(result.ValidationErrors) != 1 {
			t.Errorf("Check() expected 1 validation error, got %d", len(result.ValidationErrors))
		}

		if len(result.ValidationErrors) > 0 {
			verr := result.ValidationErrors[0]
			if verr.VendorID != "TEST" {
				t.Errorf("ValidationError.VendorID = %s, want TEST", verr.VendorID)
			}
			if verr.VendorName != "Test Vendor" {
				t.Errorf("ValidationError.VendorName = %s, want Test Vendor", verr.VendorName)
			}
			if verr.CertName != "Test Cert" {
				t.Errorf("ValidationError.CertName = %s, want Test Cert", verr.CertName)
			}
			if !strings.Contains(verr.Error.Error(), "fingerprint mismatch") {
				t.Errorf("ValidationError.Error should contain 'fingerprint mismatch', got: %v", verr.Error)
			}
		}
	})

	t.Run("certificate expiring soon", func(t *testing.T) {
		certDER, fingerprint := testutil.GenerateTestCertExpiringSoon(t, 30)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(certDER)
		}))
		defer server.Close()

		cfg := &config.TPMRootsConfig{
			Version: "test",
			Vendors: []config.Vendor{
				{
					ID:   "TEST",
					Name: "Test Vendor",
					Certificates: []config.Certificate{
						{
							Name: "Expiring Cert",
							URL:  server.URL,
							Validation: config.Validation{
								Fingerprint: config.Fingerprint{
									SHA1: formatFingerprintWithColons(fingerprint),
								},
							},
						},
					},
				},
			},
		}

		checker := &Checker{
			downloader: &download.Client{HTTPClient: server.Client()},
		}

		result, err := checker.Check(cfg, 1, 90)
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}

		if len(result.ExpirationWarnings) != 1 {
			t.Errorf("Check() expected 1 expiration warning, got %d", len(result.ExpirationWarnings))
		}

		if len(result.ExpirationWarnings) > 0 {
			warn := result.ExpirationWarnings[0]
			if warn.VendorID != "TEST" {
				t.Errorf("ExpirationWarning.VendorID = %s, want TEST", warn.VendorID)
			}
			if warn.IsExpired {
				t.Error("ExpirationWarning.IsExpired should be false")
			}
			if warn.DaysLeft < 0 || warn.DaysLeft > 90 {
				t.Errorf("ExpirationWarning.DaysLeft = %d, should be between 0 and 90", warn.DaysLeft)
			}
		}
	})

	t.Run("expired certificate", func(t *testing.T) {
		certDER, fingerprint := testutil.GenerateTestCertExpired(t)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(certDER)
		}))
		defer server.Close()

		cfg := &config.TPMRootsConfig{
			Version: "test",
			Vendors: []config.Vendor{
				{
					ID:   "TEST",
					Name: "Test Vendor",
					Certificates: []config.Certificate{
						{
							Name: "Expired Cert",
							URL:  server.URL,
							Validation: config.Validation{
								Fingerprint: config.Fingerprint{
									SHA1: formatFingerprintWithColons(fingerprint),
								},
							},
						},
					},
				},
			},
		}

		checker := &Checker{
			downloader: &download.Client{HTTPClient: server.Client()},
		}

		result, err := checker.Check(cfg, 1, 90)
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}

		if len(result.ExpirationWarnings) != 1 {
			t.Errorf("Check() expected 1 expiration warning, got %d", len(result.ExpirationWarnings))
		}

		if len(result.ExpirationWarnings) > 0 {
			warn := result.ExpirationWarnings[0]
			if !warn.IsExpired {
				t.Error("ExpirationWarning.IsExpired should be true")
			}
			if warn.DaysLeft >= 0 {
				t.Errorf("ExpirationWarning.DaysLeft = %d, should be negative for expired cert", warn.DaysLeft)
			}
		}
	})

	t.Run("download failure", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		cfg := &config.TPMRootsConfig{
			Version: "test",
			Vendors: []config.Vendor{
				{
					ID:   "TEST",
					Name: "Test Vendor",
					Certificates: []config.Certificate{
						{
							Name: "Missing Cert",
							URL:  server.URL,
							Validation: config.Validation{
								Fingerprint: config.Fingerprint{
									SHA1: "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
								},
							},
						},
					},
				},
			},
		}

		checker := &Checker{
			downloader: &download.Client{HTTPClient: server.Client()},
		}

		_, err := checker.Check(cfg, 1, 90)
		if err == nil {
			t.Error("Check() expected error for download failure")
		}
		if !strings.Contains(err.Error(), "failed to download certificate") {
			t.Errorf("Check() error should contain 'failed to download certificate', got: %v", err)
		}
	})

	t.Run("multiple vendors concurrent", func(t *testing.T) {
		certDER1, fp1 := testutil.GenerateTestCertDER(t)
		certDER2, fp2 := testutil.GenerateTestCertDER(t)

		server1 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(certDER1)
		}))
		defer server1.Close()

		server2 := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write(certDER2)
		}))
		defer server2.Close()

		cfg := &config.TPMRootsConfig{
			Vendors: []config.Vendor{
				{
					ID:   "VENDOR1",
					Name: "Vendor 1",
					Certificates: []config.Certificate{
						{
							Name: "Cert 1",
							URL:  server1.URL,
							Validation: config.Validation{
								Fingerprint: config.Fingerprint{
									SHA1: formatFingerprintWithColons(fp1),
								},
							},
						},
					},
				},
				{
					ID:   "VENDOR2",
					Name: "Vendor 2",
					Certificates: []config.Certificate{
						{
							Name: "Cert 2",
							URL:  server2.URL,
							Validation: config.Validation{
								Fingerprint: config.Fingerprint{
									SHA1: formatFingerprintWithColons(fp2),
								},
							},
						},
					},
				},
			},
		}

		checker1 := &Checker{
			downloader: &download.Client{HTTPClient: server1.Client()},
		}
		checker2 := &Checker{
			downloader: &download.Client{HTTPClient: server2.Client()},
		}

		// Use vendor-specific clients
		cfg1 := &config.TPMRootsConfig{
			Version: "test",
			Vendors: []config.Vendor{cfg.Vendors[0]},
		}
		result1, err := checker1.Check(cfg1, 2, 90)
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}

		cfg2 := &config.TPMRootsConfig{
			Version: "test",
			Vendors: []config.Vendor{cfg.Vendors[1]},
		}
		result2, err := checker2.Check(cfg2, 2, 90)
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}

		if result1.HasIssues() || result2.HasIssues() {
			t.Error("Check() expected no issues for concurrent vendor processing")
		}
	})
}

func TestValidationError_String(t *testing.T) {
	testErr := errors.New("test error")
	verr := ValidationError{
		VendorID:   "TEST",
		VendorName: "Test Vendor",
		CertName:   "Test Certificate",
		Error:      testErr,
	}

	s := verr.String()

	if !strings.Contains(s, "Test Vendor (TEST)") {
		t.Error("ValidationError.String() should contain vendor info")
	}
	if !strings.Contains(s, "Test Certificate") {
		t.Error("ValidationError.String() should contain certificate name")
	}
	if !strings.Contains(s, testErr.Error()) {
		t.Error("ValidationError.String() should contain error message")
	}
}

func TestExpirationWarning_String(t *testing.T) {
	t.Run("expiring soon", func(t *testing.T) {
		warn := ExpirationWarning{
			VendorID:   "TEST",
			VendorName: "Test Vendor",
			CertName:   "Test Certificate",
			DaysLeft:   30,
			IsExpired:  false,
			ExpiryDate: time.Now().AddDate(0, 0, 30),
		}

		s := warn.String()

		if !strings.Contains(s, "Test Vendor (TEST)") {
			t.Error("ExpirationWarning.String() should contain vendor info")
		}
		if !strings.Contains(s, "Test Certificate") {
			t.Error("ExpirationWarning.String() should contain certificate name")
		}
		if !strings.Contains(s, "Expires in 30 days") {
			t.Error("ExpirationWarning.String() should contain expiration countdown")
		}
	})

	t.Run("expired", func(t *testing.T) {
		expiryDate := time.Now().AddDate(0, 0, -10)
		warn := ExpirationWarning{
			VendorID:   "TEST",
			VendorName: "Test Vendor",
			CertName:   "Test Certificate",
			DaysLeft:   -10,
			IsExpired:  true,
			ExpiryDate: expiryDate,
		}

		s := warn.String()

		if !strings.Contains(s, "Expired on") {
			t.Error("ExpirationWarning.String() should contain 'Expired on' for expired certificates")
		}
		if !strings.Contains(s, expiryDate.Format("2006-01-02")) {
			t.Error("ExpirationWarning.String() should contain expiry date")
		}
	})
}

func TestResult_HasIssues(t *testing.T) {
	t.Run("no issues", func(t *testing.T) {
		r := &Result{
			ValidationErrors:   []ValidationError{},
			ExpirationWarnings: []ExpirationWarning{},
		}
		if r.HasIssues() {
			t.Error("HasIssues() should return false when there are no issues")
		}
	})

	t.Run("validation errors only", func(t *testing.T) {
		r := &Result{
			ValidationErrors: []ValidationError{
				{VendorID: "TEST", VendorName: "Test", CertName: "Cert", Error: errors.New("test error")},
			},
			ExpirationWarnings: []ExpirationWarning{},
		}
		if !r.HasIssues() {
			t.Error("HasIssues() should return true when there are validation errors")
		}
	})

	t.Run("expiration warnings only", func(t *testing.T) {
		r := &Result{
			ValidationErrors: []ValidationError{},
			ExpirationWarnings: []ExpirationWarning{
				{VendorID: "TEST", VendorName: "Test", CertName: "Cert", DaysLeft: 30},
			},
		}
		if !r.HasIssues() {
			t.Error("HasIssues() should return true when there are expiration warnings")
		}
	})

	t.Run("both validation errors and expiration warnings", func(t *testing.T) {
		r := &Result{
			ValidationErrors: []ValidationError{
				{VendorID: "TEST", VendorName: "Test", CertName: "Cert1", Error: errors.New("test error")},
			},
			ExpirationWarnings: []ExpirationWarning{
				{VendorID: "TEST", VendorName: "Test", CertName: "Cert2", DaysLeft: 30},
			},
		}
		if !r.HasIssues() {
			t.Error("HasIssues() should return true when there are both validation errors and expiration warnings")
		}
	})
}

// formatFingerprintWithColons converts a hex string to colon-separated format.
func formatFingerprintWithColons(fp string) string {
	decoded, _ := hex.DecodeString(fp)
	formatted := hex.EncodeToString(decoded)
	var result strings.Builder
	for i := 0; i < len(formatted); i += 2 {
		if i > 0 {
			result.WriteString(":")
		}
		result.WriteString(strings.ToUpper(formatted[i : i+2]))
	}
	return result.String()
}
