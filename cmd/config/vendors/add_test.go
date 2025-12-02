package vendors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
	"go.yaml.in/yaml/v4"
)

func TestAddCommand(t *testing.T) {
	tests := []struct {
		name           string
		initialConfig  string
		opts           addOptions
		expectError    bool
		errorContains  string
		validateResult func(t *testing.T, cfg *config.TPMRootsConfig)
	}{
		{
			name: "add new vendor successfully",
			initialConfig: `version: "alpha"
vendors:
  - name: "Vendor A"
    id: "VDA"
    certificates:
      - name: "Cert A1"
        url: "https://example.com/a1.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts: addOptions{
				id:   "INTC",
				name: "Intel Corporation",
			},
			expectError: false,
			validateResult: func(t *testing.T, cfg *config.TPMRootsConfig) {
				if len(cfg.Vendors) != 2 {
					t.Fatalf("expected 2 vendors, got %d", len(cfg.Vendors))
				}

				// Check alphabetical order (INTC should come before VDA)
				if cfg.Vendors[0].ID != "INTC" {
					t.Errorf("expected first vendor ID to be 'INTC', got '%s'", cfg.Vendors[0].ID)
				}
				if cfg.Vendors[0].Name != "Intel Corporation" {
					t.Errorf("expected first vendor name to be 'Intel Corporation', got '%s'", cfg.Vendors[0].Name)
				}
				if len(cfg.Vendors[0].Certificates) != 0 {
					t.Errorf("expected new vendor to have 0 certificates, got %d", len(cfg.Vendors[0].Certificates))
				}

				if cfg.Vendors[1].ID != "VDA" {
					t.Errorf("expected second vendor ID to be 'VDA', got '%s'", cfg.Vendors[1].ID)
				}
			},
		},
		{
			name: "add vendor at the end (alphabetically)",
			initialConfig: `version: "alpha"
vendors:
  - name: "AMD"
    id: "AMD"
    certificates:
      - name: "Cert 1"
        url: "https://example.com/1.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
  - name: "Intel"
    id: "INTC"
    certificates:
      - name: "Cert 2"
        url: "https://example.com/2.crt"
        validation:
          fingerprint:
            sha1: "BB:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts: addOptions{
				id:   "QCOM",
				name: "Qualcomm Technologies",
			},
			expectError: false,
			validateResult: func(t *testing.T, cfg *config.TPMRootsConfig) {
				if len(cfg.Vendors) != 3 {
					t.Fatalf("expected 3 vendors, got %d", len(cfg.Vendors))
				}

				// Check order: AMD, INTC, QCOM
				if cfg.Vendors[0].ID != "AMD" {
					t.Errorf("expected first vendor to be AMD, got %s", cfg.Vendors[0].ID)
				}
				if cfg.Vendors[1].ID != "INTC" {
					t.Errorf("expected second vendor to be INTC, got %s", cfg.Vendors[1].ID)
				}
				if cfg.Vendors[2].ID != "QCOM" {
					t.Errorf("expected third vendor to be QCOM, got %s", cfg.Vendors[2].ID)
				}
				if cfg.Vendors[2].Name != "Qualcomm Technologies" {
					t.Errorf("expected QCOM name to be 'Qualcomm Technologies', got '%s'", cfg.Vendors[2].Name)
				}
			},
		},
		{
			name: "add vendor in the middle (alphabetically)",
			initialConfig: `version: "alpha"
vendors:
  - name: "AMD"
    id: "AMD"
    certificates:
      - name: "Cert 1"
        url: "https://example.com/1.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
  - name: "Qualcomm"
    id: "QCOM"
    certificates:
      - name: "Cert 2"
        url: "https://example.com/2.crt"
        validation:
          fingerprint:
            sha1: "BB:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts: addOptions{
				id:   "INTC",
				name: "Intel Corporation",
			},
			expectError: false,
			validateResult: func(t *testing.T, cfg *config.TPMRootsConfig) {
				if len(cfg.Vendors) != 3 {
					t.Fatalf("expected 3 vendors, got %d", len(cfg.Vendors))
				}

				// Check order: AMD, INTC, QCOM
				if cfg.Vendors[0].ID != "AMD" {
					t.Errorf("expected first vendor to be AMD, got %s", cfg.Vendors[0].ID)
				}
				if cfg.Vendors[1].ID != "INTC" {
					t.Errorf("expected second vendor to be INTC, got %s", cfg.Vendors[1].ID)
				}
				if cfg.Vendors[2].ID != "QCOM" {
					t.Errorf("expected third vendor to be QCOM, got %s", cfg.Vendors[2].ID)
				}
			},
		},
		{
			name: "error when vendor already exists",
			initialConfig: `version: "alpha"
vendors:
  - name: "Intel Corporation"
    id: "INTC"
    certificates:
      - name: "Cert 1"
        url: "https://example.com/1.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts: addOptions{
				id:   "INTC",
				name: "Intel Corp",
			},
			expectError:   true,
			errorContains: "already exists",
		},
		{
			name: "error when vendor ID is not in TCG registry",
			initialConfig: `version: "alpha"
vendors:
  - name: "Intel Corporation"
    id: "INTC"
    certificates:
      - name: "Cert 1"
        url: "https://example.com/1.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts: addOptions{
				id:   "INVALID",
				name: "Invalid Vendor",
			},
			expectError:   true,
			errorContains: "invalid vendor ID",
		},
		{
			name: "formatter sorts vendors lexicographically",
			initialConfig: `version: "alpha"
vendors:
  - name: "alpha vendor"
    id: "alpha"
    certificates:
      - name: "Cert 1"
        url: "https://example.com/1.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
  - name: "charlie vendor"
    id: "charlie"
    certificates:
      - name: "Cert 2"
        url: "https://example.com/2.crt"
        validation:
          fingerprint:
            sha1: "BB:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts: addOptions{
				id:   "AMD",
				name: "AMD",
			},
			expectError: false,
			validateResult: func(t *testing.T, cfg *config.TPMRootsConfig) {
				if len(cfg.Vendors) != 3 {
					t.Fatalf("expected 3 vendors, got %d", len(cfg.Vendors))
				}

				// The formatter sorts lexicographically: uppercase letters come before lowercase
				// So the order is: AMD, alpha, charlie
				if cfg.Vendors[0].ID != "AMD" {
					t.Errorf("expected first vendor to be AMD, got %s", cfg.Vendors[0].ID)
				}
				if cfg.Vendors[1].ID != "alpha" {
					t.Errorf("expected second vendor to be alpha, got %s", cfg.Vendors[1].ID)
				}
				if cfg.Vendors[2].ID != "charlie" {
					t.Errorf("expected third vendor to be charlie, got %s", cfg.Vendors[2].ID)
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

			// Run the add command
			err := runAddVendor(&tt.opts)

			// Check error expectation
			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Check error message
			if tt.expectError && tt.errorContains != "" {
				if err == nil || !containsString(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain '%s', got: %v", tt.errorContains, err)
				}
			}

			// Validate result if no error expected
			if !tt.expectError && tt.validateResult != nil {
				// Load the saved config
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatalf("failed to read config: %v", err)
				}

				var cfg config.TPMRootsConfig
				if err := yaml.Unmarshal(data, &cfg); err != nil {
					t.Fatalf("failed to parse config: %v", err)
				}

				tt.validateResult(t, &cfg)
			}
		})
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
