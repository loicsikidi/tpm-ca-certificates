package sanity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config/sanity"
	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
)

func TestSanityCommand(t *testing.T) {
	tests := []struct {
		name           string
		quiet          bool
		threshold      int
		expectExit     bool
		expectOutput   bool
		outputContains []string
	}{
		{
			name:         "valid certificates without quiet",
			quiet:        false,
			threshold:    90,
			expectExit:   false,
			expectOutput: true,
		},
		{
			name:         "valid certificates with quiet",
			quiet:        true,
			threshold:    90,
			expectExit:   false,
			expectOutput: false,
		},
		{
			name:         "fingerprint mismatch without quiet",
			quiet:        false,
			threshold:    90,
			expectExit:   true,
			expectOutput: true,
			outputContains: []string{
				"validation errors",
				"fingerprint mismatch",
			},
		},
		{
			name:         "fingerprint mismatch with quiet",
			quiet:        true,
			threshold:    90,
			expectExit:   true,
			expectOutput: false,
		},
		{
			name:         "certificate expiring soon",
			quiet:        false,
			threshold:    90,
			expectExit:   true,
			expectOutput: true,
			outputContains: []string{
				"expiration warnings",
				"Expires in",
			},
		},
		{
			name:         "expired certificate",
			quiet:        false,
			threshold:    90,
			expectExit:   true,
			expectOutput: true,
			outputContains: []string{
				"expiration warnings",
				"Expired on",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate test certificates based on test case
			var certDER []byte
			var fingerprint string

			switch tt.name {
			case "valid certificates without quiet", "valid certificates with quiet":
				certDER, fingerprint = testutil.GenerateTestCertDER(t)
			case "fingerprint mismatch without quiet", "fingerprint mismatch with quiet":
				certDER, _ = testutil.GenerateTestCertDER(t)
				fingerprint = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33"
			case "certificate expiring soon":
				certDER, fingerprint = testutil.GenerateTestCertExpiringSoon(t, 30)
			case "expired certificate":
				certDER, fingerprint = testutil.GenerateTestCertExpired(t)
			}

			// Create test server
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write(certDER)
			}))
			defer server.Close()

			// Create temporary config file
			tmpDir := t.TempDir()
			configPath = filepath.Join(tmpDir, ".tpm-roots.yaml")

			configContent := `---
version: "test"
vendors:
  - id: "TEST"
    name: "Test Vendor"
    certificates:
      - name: "Test Certificate"
        url: "` + server.URL + `"
        validation:
          fingerprint:
            sha1: "` + formatFingerprintWithColons(fingerprint) + `"
`
			if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
				t.Fatalf("failed to create test config: %v", err)
			}

			// Set flags
			quiet = tt.quiet
			threshold = tt.threshold
			workers = 1

			// Mock checker with server's HTTP client
			checkerGetter = func() *sanity.Checker {
				return sanity.NewCheckerWithClient(server.Client())
			}

			// Capture stdout and stderr
			oldStdout := os.Stdout
			oldStderr := os.Stderr
			rOut, wOut, _ := os.Pipe()
			rErr, wErr, _ := os.Pipe()
			os.Stdout = wOut
			os.Stderr = wErr

			// Track if os.Exit was called
			exitCalled := false
			osExit = func(code int) {
				exitCalled = true
				if code != 1 {
					t.Errorf("expected exit code 1, got %d", code)
				}
			}

			// Run the command
			err := run(nil, nil)

			// Restore stdout/stderr
			wOut.Close()
			wErr.Close()
			os.Stdout = oldStdout
			os.Stderr = oldStderr

			// Read captured output
			var bufOut bytes.Buffer
			var bufErr bytes.Buffer
			io.Copy(&bufOut, rOut)
			io.Copy(&bufErr, rErr)
			output := bufOut.String() + bufErr.String()

			// Check exit behavior
			if tt.expectExit && !exitCalled {
				t.Error("expected os.Exit to be called but it wasn't")
			}
			if !tt.expectExit && exitCalled {
				t.Error("expected os.Exit not to be called but it was")
			}

			// Check error
			if !tt.expectExit && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check output
			if tt.expectOutput && output == "" {
				t.Error("expected output but got none")
			}
			if !tt.expectOutput && output != "" {
				t.Errorf("expected no output but got: %s", output)
			}

			// Check output contains expected strings
			for _, substr := range tt.outputContains {
				if !strings.Contains(output, substr) {
					t.Errorf("expected output to contain '%s', got: %s", substr, output)
				}
			}

			// Reset osExit and checkerGetter
			osExit = os.Exit
			checkerGetter = sanity.NewChecker
		})
	}
}

func TestSanityCommand_ConfigNotFound(t *testing.T) {
	configPath = "/tmp/nonexistent-config.yaml"
	quiet = false
	threshold = 90
	workers = 1

	err := run(nil, nil)
	if err == nil {
		t.Error("expected error for missing config file")
	}
	if !strings.Contains(err.Error(), "failed to load configuration") {
		t.Errorf("expected error to contain 'failed to load configuration', got: %v", err)
	}
}

func TestSanityCommand_InvalidWorkers(t *testing.T) {
	tmpDir := t.TempDir()
	configPath = filepath.Join(tmpDir, ".tpm-roots.yaml")

	configContent := `---
version: "test"
vendors:
  - id: "TEST"
    name: "Test Vendor"
    certificates:
      - name: "Test Certificate"
        url: "https://example.com/cert.crt"
        validation:
          fingerprint:
            sha256: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to create test config: %v", err)
	}

	quiet = false
	threshold = 90
	workers = 1000 // Exceeds MaxWorkers

	err := run(nil, nil)
	if err == nil {
		t.Error("expected error for invalid workers count")
	}
	if !strings.Contains(err.Error(), "exceeds maximum allowed") {
		t.Errorf("expected error to contain 'exceeds maximum allowed', got: %v", err)
	}
}

func TestDisplayResults(t *testing.T) {
	t.Run("validation errors only", func(t *testing.T) {
		result := &sanity.Result{
			ValidationErrors: []sanity.ValidationError{
				{
					VendorID:   "TEST",
					VendorName: "Test Vendor",
					CertName:   "Test Cert",
					Error:      errors.New("test error"),
				},
			},
			ExpirationWarnings: []sanity.ExpirationWarning{},
		}

		// Capture stderr
		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		displayResults(result)

		w.Close()
		os.Stderr = oldStderr

		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.String()

		if !strings.Contains(output, "validation errors") {
			t.Error("expected output to contain 'validation errors'")
		}
		if !strings.Contains(output, "Test Vendor (TEST)") {
			t.Error("expected output to contain vendor info")
		}
	})

	t.Run("expiration warnings only", func(t *testing.T) {
		result := &sanity.Result{
			ValidationErrors: []sanity.ValidationError{},
			ExpirationWarnings: []sanity.ExpirationWarning{
				{
					VendorID:   "TEST",
					VendorName: "Test Vendor",
					CertName:   "Test Cert",
					DaysLeft:   30,
					IsExpired:  false,
				},
			},
		}

		// Capture stderr
		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		displayResults(result)

		w.Close()
		os.Stderr = oldStderr

		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.String()

		if !strings.Contains(output, "expiration warnings") {
			t.Error("expected output to contain 'expiration warnings'")
		}
		if !strings.Contains(output, "Expires in 30 days") {
			t.Error("expected output to contain expiration countdown")
		}
	})

	t.Run("both errors and warnings", func(t *testing.T) {
		result := &sanity.Result{
			ValidationErrors: []sanity.ValidationError{
				{
					VendorID:   "TEST1",
					VendorName: "Test Vendor 1",
					CertName:   "Test Cert 1",
					Error:      errors.New("test error"),
				},
			},
			ExpirationWarnings: []sanity.ExpirationWarning{
				{
					VendorID:   "TEST2",
					VendorName: "Test Vendor 2",
					CertName:   "Test Cert 2",
					DaysLeft:   30,
					IsExpired:  false,
				},
			},
		}

		// Capture stderr
		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		displayResults(result)

		w.Close()
		os.Stderr = oldStderr

		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.String()

		if !strings.Contains(output, "validation errors") {
			t.Error("expected output to contain 'validation errors'")
		}
		if !strings.Contains(output, "expiration warnings") {
			t.Error("expected output to contain 'expiration warnings'")
		}
	})

	t.Run("truncate to max errors", func(t *testing.T) {
		// Create more than maxErrors validation errors
		errs := make([]sanity.ValidationError, 15)
		for i := 0; i < 15; i++ {
			errs[i] = sanity.ValidationError{
				VendorID:   "TEST",
				VendorName: "Test Vendor",
				CertName:   "Test Cert",
				Error:      errors.New("test error"),
			}
		}

		result := &sanity.Result{
			ValidationErrors:   errs,
			ExpirationWarnings: []sanity.ExpirationWarning{},
		}

		// Capture stderr
		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		displayResults(result)

		w.Close()
		os.Stderr = oldStderr

		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.String()

		if !strings.Contains(output, "showing first 10 errors") {
			t.Error("expected output to indicate truncation")
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
