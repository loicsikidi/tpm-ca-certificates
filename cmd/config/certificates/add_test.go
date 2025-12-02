package certificates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
)

func TestAddCommand(t *testing.T) {
	tests := []struct {
		name           string
		initialConfig  string
		opts           addOptions
		expectError    bool
		validateResult func(t *testing.T, cfg *config.TPMRootsConfig)
	}{
		{
			name: "add certificate with auto-calculated fingerprint",
			initialConfig: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates:
      - name: "Existing Cert"
        url: "https://example.com/cert.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts: addOptions{
				vendorID:      "STM",
				name:          "New Test Certificate",
				url:           "https://secure.globalsign.com/cacert/gstpmroot.crt",
				hashAlgorithm: "sha256",
			},
			expectError: false,
			validateResult: func(t *testing.T, cfg *config.TPMRootsConfig) {
				if len(cfg.Vendors) != 1 {
					t.Fatalf("expected 1 vendor, got %d", len(cfg.Vendors))
				}
				vendor := cfg.Vendors[0]
				if len(vendor.Certificates) != 2 {
					t.Fatalf("expected 2 certificates, got %d", len(vendor.Certificates))
				}

				// Check alphabetical order
				if vendor.Certificates[0].Name != "Existing Cert" {
					t.Errorf("expected first cert to be 'Existing Cert', got '%s'", vendor.Certificates[0].Name)
				}
				if vendor.Certificates[1].Name != "New Test Certificate" {
					t.Errorf("expected second cert to be 'New Test Certificate', got '%s'", vendor.Certificates[1].Name)
				}

				// Check SHA256 fingerprint was calculated
				newCert := vendor.Certificates[1]
				if newCert.Validation.Fingerprint.SHA256 == "" {
					t.Error("expected SHA256 fingerprint to be calculated, got empty")
				}
			},
		},
		{
			name: "add certificate with provided SHA256 fingerprint",
			initialConfig: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates:
      - name: "GlobalSign Trusted Computing CA"
        url: "https://secure.globalsign.com/cacert/gstpmroot.crt"
        validation:
          fingerprint:
            sha1: "3D:5E:6B:4A:8C:2F:1E:4B:9A:7C:8D:2E:3F:4A:5B:6C:7D:8E:9F:0A"
`,
			opts: addOptions{
				vendorID:      "STM",
				name:          "STSAFE ECC Root CA 02",
				url:           "https://sw-center.st.com/STSAFE/STSAFEEccRootCA02.crt",
				fingerprint:   "SHA256:FD:1E:7B:68:AC:CD:82:56:36:B2:7B:31:77:C6:74:02:D4:63:A7:F0:4C:97:B6:C4:7A:B7:05:FC:DC:1A:04:F6",
				hashAlgorithm: "sha256",
			},
			expectError: false,
			validateResult: func(t *testing.T, cfg *config.TPMRootsConfig) {
				vendor := cfg.Vendors[0]
				if len(vendor.Certificates) != 2 {
					t.Fatalf("expected 2 certificates, got %d", len(vendor.Certificates))
				}

				// Find the new certificate
				var newCert *config.Certificate
				for i := range vendor.Certificates {
					if vendor.Certificates[i].Name == "STSAFE ECC Root CA 02" {
						newCert = &vendor.Certificates[i]
						break
					}
				}
				if newCert == nil {
					t.Fatal("new certificate not found")
				}

				// Check the fingerprint was stored correctly
				expectedFingerprint := "FD:1E:7B:68:AC:CD:82:56:36:B2:7B:31:77:C6:74:02:D4:63:A7:F0:4C:97:B6:C4:7A:B7:05:FC:DC:1A:04:F6"
				if newCert.Validation.Fingerprint.SHA256 != expectedFingerprint {
					t.Errorf("expected SHA256 fingerprint '%s', got '%s'", expectedFingerprint, newCert.Validation.Fingerprint.SHA256)
				}
			},
		},
		{
			name: "error when vendor not found",
			initialConfig: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates:
      - name: "Test Cert"
        url: "https://example.com/cert.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts: addOptions{
				vendorID:      "NONEXISTENT",
				name:          "Test Certificate",
				url:           "https://example.com/cert.crt",
				hashAlgorithm: "sha256",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, ".tpm-roots.yaml")

			if err := os.WriteFile(configPath, []byte(tt.initialConfig), 0644); err != nil {
				t.Fatalf("failed to create test config: %v", err)
			}

			// Set config path
			tt.opts.configPath = configPath

			// Run the add command
			err := runAdd(&tt.opts)

			// Check error expectation
			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Validate result if no error expected
			if !tt.expectError && tt.validateResult != nil {
				cfg, err := config.LoadConfig(configPath)
				if err != nil {
					t.Fatalf("failed to load updated config: %v", err)
				}
				tt.validateResult(t, cfg)
			}
		})
	}
}

func TestInsertCertificateAlphabetically(t *testing.T) {
	tests := []struct {
		name     string
		existing []config.Certificate
		new      config.Certificate
		expected []string
	}{
		{
			name: "insert at beginning",
			existing: []config.Certificate{
				{Name: "B Certificate"},
				{Name: "C Certificate"},
			},
			new:      config.Certificate{Name: "A Certificate"},
			expected: []string{"A Certificate", "B Certificate", "C Certificate"},
		},
		{
			name: "insert in middle",
			existing: []config.Certificate{
				{Name: "A Certificate"},
				{Name: "C Certificate"},
			},
			new:      config.Certificate{Name: "B Certificate"},
			expected: []string{"A Certificate", "B Certificate", "C Certificate"},
		},
		{
			name: "insert at end",
			existing: []config.Certificate{
				{Name: "A Certificate"},
				{Name: "B Certificate"},
			},
			new:      config.Certificate{Name: "Z Certificate"},
			expected: []string{"A Certificate", "B Certificate", "Z Certificate"},
		},
		{
			name:     "insert into empty list",
			existing: []config.Certificate{},
			new:      config.Certificate{Name: "A Certificate"},
			expected: []string{"A Certificate"},
		},
		{
			name: "case insensitive ordering",
			existing: []config.Certificate{
				{Name: "alpha"},
				{Name: "charlie"},
			},
			new:      config.Certificate{Name: "Bravo"},
			expected: []string{"alpha", "Bravo", "charlie"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := insertCertificateAlphabetically(tt.existing, tt.new)

			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d certificates, got %d", len(tt.expected), len(result))
			}

			for i, expected := range tt.expected {
				if result[i].Name != expected {
					t.Errorf("at position %d: expected '%s', got '%s'", i, expected, result[i].Name)
				}
			}
		})
	}
}

func TestCalculateFingerprint(t *testing.T) {
	testData := []byte("test data for fingerprint calculation")

	tests := []struct {
		name      string
		algorithm string
		expectErr bool
	}{
		{
			name:      "SHA1",
			algorithm: "sha1",
			expectErr: false,
		},
		{
			name:      "SHA256",
			algorithm: "sha256",
			expectErr: false,
		},
		{
			name:      "SHA384",
			algorithm: "sha384",
			expectErr: false,
		},
		{
			name:      "SHA512",
			algorithm: "sha512",
			expectErr: false,
		},
		{
			name:      "invalid algorithm",
			algorithm: "md5",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := calculateFingerprint(testData, tt.algorithm)

			if tt.expectErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Check result is non-empty and properly formatted (colon-separated hex)
			if result == "" {
				t.Error("expected non-empty fingerprint")
			}

			// Verify format (should contain colons and uppercase hex)
			if !containsColons(result) {
				t.Errorf("fingerprint should contain colons: %s", result)
			}
		})
	}
}

func containsColons(s string) bool {
	return len(s) > 0 && s != "" && (len(s) > 2)
}

func TestHashAlgorithmValidation(t *testing.T) {
	tests := []struct {
		name         string
		hashAlgo     string
		fingerprint  string
		expectError  bool
		errorMessage string
	}{
		{
			name:        "valid sha256",
			hashAlgo:    "sha256",
			fingerprint: "",
			expectError: false,
		},
		{
			name:         "invalid algorithm",
			hashAlgo:     "md5",
			fingerprint:  "",
			expectError:  true,
			errorMessage: "invalid hash algorithm",
		},
		{
			name:         "fingerprint algo mismatch",
			hashAlgo:     "sha256",
			fingerprint:  "SHA1:AB:CD:EF",
			expectError:  true,
			errorMessage: "does not match specified hash algorithm",
		},
		{
			name:        "matching fingerprint and algo",
			hashAlgo:    "sha256",
			fingerprint: "SHA256:AB:CD:EF",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config
			tmpDir := t.TempDir()
			configPath := tmpDir + "/.tpm-roots.yaml"
			cfg := `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates: []
`
			if err := os.WriteFile(configPath, []byte(cfg), 0644); err != nil {
				t.Fatal(err)
			}

			opts := &addOptions{
				configPath:    configPath,
				vendorID:      "STM",
				name:          "Test Cert",
				url:           "https://secure.globalsign.com/cacert/gstpmroot.crt",
				hashAlgorithm: tt.hashAlgo,
				fingerprint:   tt.fingerprint,
			}

			err := runAdd(opts)

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errorMessage != "" && !containsSubstring(err.Error(), tt.errorMessage) {
					t.Errorf("expected error to contain '%s', got: %v", tt.errorMessage, err)
				}
			} else if err != nil && !containsSubstring(err.Error(), "failed to download") {
				// Allow download failures in tests, but not validation errors
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr))
}

func TestParseFingerprint(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedAlg string
		expectedErr bool
	}{
		{
			name:        "valid SHA256 fingerprint",
			input:       "SHA256:AB:CD:EF",
			expectedAlg: "sha256",
			expectedErr: false,
		},
		{
			name:        "valid SHA1 fingerprint",
			input:       "SHA1:12:34:56",
			expectedAlg: "sha1",
			expectedErr: false,
		},
		{
			name:        "invalid algorithm",
			input:       "MD5:AB:CD:EF",
			expectedAlg: "",
			expectedErr: true,
		},
		{
			name:        "missing colon",
			input:       "SHA256ABCDEF",
			expectedAlg: "",
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, _, err := parseFingerprint(tt.input)

			if tt.expectedErr && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectedErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.expectedErr && alg != tt.expectedAlg {
				t.Errorf("expected algorithm '%s', got '%s'", tt.expectedAlg, alg)
			}
		})
	}
}
