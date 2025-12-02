package certificates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
)

func TestRemoveCommand(t *testing.T) {
	tests := []struct {
		name           string
		initialConfig  string
		opts           removeOptions
		expectError    bool
		validateResult func(t *testing.T, cfg *config.TPMRootsConfig)
	}{
		{
			name: "remove existing certificate",
			initialConfig: `version: "alpha"
vendors:
  - name: "Test Vendor"
    id: "TST"
    certificates:
      - name: "Certificate A"
        url: "https://example.com/cert-a.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
      - name: "Certificate B"
        url: "https://example.com/cert-b.crt"
        validation:
          fingerprint:
            sha1: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44"
      - name: "Certificate C"
        url: "https://example.com/cert-c.crt"
        validation:
          fingerprint:
            sha1: "FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC"
`,
			opts: removeOptions{
				vendorID: "TST",
				name:     "Certificate B",
			},
			expectError: false,
			validateResult: func(t *testing.T, cfg *config.TPMRootsConfig) {
				if len(cfg.Vendors) != 1 {
					t.Fatalf("expected 1 vendor, got %d", len(cfg.Vendors))
				}
				vendor := cfg.Vendors[0]
				if len(vendor.Certificates) != 2 {
					t.Fatalf("expected 2 certificates after removal, got %d", len(vendor.Certificates))
				}

				// Check remaining certificates
				names := []string{vendor.Certificates[0].Name, vendor.Certificates[1].Name}
				if names[0] != "Certificate A" || names[1] != "Certificate C" {
					t.Errorf("expected remaining certs 'Certificate A' and 'Certificate C', got %v", names)
				}
			},
		},
		{
			name: "case insensitive certificate name matching",
			initialConfig: `version: "alpha"
vendors:
  - name: "Test Vendor"
    id: "TST"
    certificates:
      - name: "FirstCert"
        url: "https://example.com/first.crt"
        validation:
          fingerprint:
            sha1: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44"
      - name: "MyTestCertificate"
        url: "https://example.com/cert.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts: removeOptions{
				vendorID: "TST",
				name:     "mytestcertificate",
			},
			expectError: false,
			validateResult: func(t *testing.T, cfg *config.TPMRootsConfig) {
				vendor := cfg.Vendors[0]
				if len(vendor.Certificates) != 1 {
					t.Fatalf("expected 1 certificate after removal, got %d", len(vendor.Certificates))
				}
				if vendor.Certificates[0].Name != "FirstCert" {
					t.Errorf("expected remaining cert 'FirstCert', got '%s'", vendor.Certificates[0].Name)
				}
			},
		},
		{
			name: "error when vendor not found",
			initialConfig: `version: "alpha"
vendors:
  - name: "Test Vendor"
    id: "TST"
    certificates:
      - name: "Test Cert"
        url: "https://example.com/cert.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts: removeOptions{
				vendorID: "NONEXISTENT",
				name:     "Test Cert",
			},
			expectError: true,
		},
		{
			name: "error when certificate not found",
			initialConfig: `version: "alpha"
vendors:
  - name: "Test Vendor"
    id: "TST"
    certificates:
      - name: "Certificate A"
        url: "https://example.com/cert-a.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts: removeOptions{
				vendorID: "TST",
				name:     "Nonexistent Certificate",
			},
			expectError: true,
		},
		{
			name: "remove first certificate from list",
			initialConfig: `version: "alpha"
vendors:
  - name: "Test Vendor"
    id: "TST"
    certificates:
      - name: "First Cert"
        url: "https://example.com/first.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
      - name: "Second Cert"
        url: "https://example.com/second.crt"
        validation:
          fingerprint:
            sha1: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44"
`,
			opts: removeOptions{
				vendorID: "TST",
				name:     "First Cert",
			},
			expectError: false,
			validateResult: func(t *testing.T, cfg *config.TPMRootsConfig) {
				vendor := cfg.Vendors[0]
				if len(vendor.Certificates) != 1 {
					t.Fatalf("expected 1 certificate after removal, got %d", len(vendor.Certificates))
				}
				if vendor.Certificates[0].Name != "Second Cert" {
					t.Errorf("expected remaining cert 'Second Cert', got '%s'", vendor.Certificates[0].Name)
				}
			},
		},
		{
			name: "remove last certificate from list",
			initialConfig: `version: "alpha"
vendors:
  - name: "Test Vendor"
    id: "TST"
    certificates:
      - name: "First Cert"
        url: "https://example.com/first.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
      - name: "Last Cert"
        url: "https://example.com/last.crt"
        validation:
          fingerprint:
            sha1: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44"
`,
			opts: removeOptions{
				vendorID: "TST",
				name:     "Last Cert",
			},
			expectError: false,
			validateResult: func(t *testing.T, cfg *config.TPMRootsConfig) {
				vendor := cfg.Vendors[0]
				if len(vendor.Certificates) != 1 {
					t.Fatalf("expected 1 certificate after removal, got %d", len(vendor.Certificates))
				}
				if vendor.Certificates[0].Name != "First Cert" {
					t.Errorf("expected remaining cert 'First Cert', got '%s'", vendor.Certificates[0].Name)
				}
			},
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

			// Run the remove command
			err := runRemove(&tt.opts)

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
