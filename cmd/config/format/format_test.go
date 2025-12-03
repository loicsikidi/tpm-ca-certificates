package format

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
)

func TestFormatCommand(t *testing.T) {
	tests := []struct {
		name           string
		initialConfig  string
		dryRun         bool
		expectError    bool
		validateResult func(t *testing.T, configPath string)
	}{
		{
			name: "format unformatted file",
			initialConfig: `version: alpha
vendors:
  - id: TV
    name: Test Vendor
    certificates:
      - name: Test Cert
        url: https://example.com/test.cer
        validation:
          fingerprint:
            sha1: aa:bb:cc:dd
`,
			dryRun:      false,
			expectError: false,
			validateResult: func(t *testing.T, configPath string) {
				cfg, err := config.LoadConfig(configPath)
				if err != nil {
					t.Fatalf("failed to load formatted config: %v", err)
				}

				// Verify vendor exists
				if len(cfg.Vendors) != 1 {
					t.Fatalf("expected 1 vendor, got %d", len(cfg.Vendors))
				}

				// Verify certificate fingerprint is uppercase
				cert := cfg.Vendors[0].Certificates[0]
				if cert.Validation.Fingerprint.SHA1 != "AA:BB:CC:DD" {
					t.Errorf("expected uppercase fingerprint 'AA:BB:CC:DD', got '%s'", cert.Validation.Fingerprint.SHA1)
				}

				// Read the raw file to check quotes
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatalf("failed to read formatted file: %v", err)
				}
				content := string(data)

				// Check that strings are quoted
				if !contains(content, `"alpha"`) {
					t.Error("expected version to be quoted")
				}
				if !contains(content, `"Test Vendor"`) {
					t.Error("expected vendor name to be quoted")
				}
			},
		},
		{
			name: "format file with unsorted vendors",
			initialConfig: `version: "alpha"
vendors:
  - id: "VB"
    name: "Vendor B"
    certificates:
      - name: "Cert"
        url: "https://example.com/b.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD"
  - id: "VA"
    name: "Vendor A"
    certificates:
      - name: "Cert"
        url: "https://example.com/a.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD"
`,
			dryRun:      false,
			expectError: false,
			validateResult: func(t *testing.T, configPath string) {
				cfg, err := config.LoadConfig(configPath)
				if err != nil {
					t.Fatalf("failed to load formatted config: %v", err)
				}

				// Verify vendors are sorted alphabetically by ID
				if len(cfg.Vendors) != 2 {
					t.Fatalf("expected 2 vendors, got %d", len(cfg.Vendors))
				}
				if cfg.Vendors[0].ID != "VA" {
					t.Errorf("expected first vendor ID to be 'VA', got '%s'", cfg.Vendors[0].ID)
				}
				if cfg.Vendors[1].ID != "VB" {
					t.Errorf("expected second vendor ID to be 'VB', got '%s'", cfg.Vendors[1].ID)
				}
			},
		},
		{
			name: "format file with unsorted certificates",
			initialConfig: `version: "alpha"
vendors:
  - id: "TV"
    name: "Test Vendor"
    certificates:
      - name: "Z Certificate"
        url: "https://example.com/z.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD"
      - name: "A Certificate"
        url: "https://example.com/a.cer"
        validation:
          fingerprint:
            sha1: "EE:FF:00:11"
`,
			dryRun:      false,
			expectError: false,
			validateResult: func(t *testing.T, configPath string) {
				cfg, err := config.LoadConfig(configPath)
				if err != nil {
					t.Fatalf("failed to load formatted config: %v", err)
				}

				vendor := cfg.Vendors[0]
				if len(vendor.Certificates) != 2 {
					t.Fatalf("expected 2 certificates, got %d", len(vendor.Certificates))
				}

				// Verify certificates are sorted alphabetically
				if vendor.Certificates[0].Name != "A Certificate" {
					t.Errorf("expected first cert to be 'A Certificate', got '%s'", vendor.Certificates[0].Name)
				}
				if vendor.Certificates[1].Name != "Z Certificate" {
					t.Errorf("expected second cert to be 'Z Certificate', got '%s'", vendor.Certificates[1].Name)
				}
			},
		},
		{
			name: "dry-run on unformatted file returns error",
			initialConfig: `version: alpha
vendors:
  - id: TV
    name: Test Vendor
    certificates:
      - name: Test Cert
        url: https://example.com/test.cer
        validation:
          fingerprint:
            sha1: aa:bb:cc:dd
`,
			dryRun:      true,
			expectError: true,
			validateResult: func(t *testing.T, configPath string) {
				// Verify file was not modified
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatalf("failed to read file: %v", err)
				}

				content := string(data)
				// File should still have unformatted content
				if contains(content, `"alpha"`) {
					t.Error("file should not have been modified in dry-run mode")
				}
				if !contains(content, "version: alpha") {
					t.Error("file content was unexpectedly changed")
				}
			},
		},
		{
			name: "dry-run on formatted file succeeds",
			initialConfig: `---
version: "alpha"
vendors:
    - id: "TV"
      name: "Test Vendor"
      certificates:
        - name: "Test Cert"
          url: "https://example.com/test.cer"
          validation:
            fingerprint:
                sha1: "AA:BB:CC:DD"
`,
			dryRun:      true,
			expectError: false,
			validateResult: func(t *testing.T, configPath string) {
				// Verify file was not modified
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatalf("failed to read file: %v", err)
				}

				content := string(data)
				// Should still be formatted
				if !contains(content, `"alpha"`) {
					t.Error("formatted file should still have quotes")
				}
			},
		},
		{
			name: "format file with URL encoding",
			initialConfig: `version: "alpha"
vendors:
  - id: "TV"
    name: "Test Vendor"
    certificates:
      - name: "Test Cert"
        url: "https://example.com/test cert with spaces.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD"
`,
			dryRun:      false,
			expectError: false,
			validateResult: func(t *testing.T, configPath string) {
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatalf("failed to read formatted file: %v", err)
				}

				content := string(data)
				// Check URL is encoded
				if !contains(content, "test%20cert%20with%20spaces.cer") {
					t.Error("expected URL to be encoded with %20 for spaces")
				}
			},
		},
		{
			name: "error on invalid config",
			initialConfig: `version: alpha
invalid yaml content:
  - this is not: valid: yaml:
`,
			dryRun:      false,
			expectError: true,
			validateResult: func(t *testing.T, configPath string) {
				// No validation needed for error case
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

			// Store original content for comparison
			originalContent, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatalf("failed to read original config: %v", err)
			}

			// Run the format command
			cmd := NewCommand()
			cmd.SetArgs([]string{"--config", configPath})
			if tt.dryRun {
				cmd.SetArgs([]string{"--config", configPath, "--dry-run"})
			}

			err = cmd.Execute()

			// Check error expectation
			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// In dry-run mode, verify file wasn't modified (except for formatted case)
			if tt.dryRun && !tt.expectError {
				currentContent, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatalf("failed to read current config: %v", err)
				}
				if string(currentContent) != string(originalContent) {
					t.Error("file should not be modified in dry-run mode when already formatted")
				}
			}

			// Run validation if provided
			if tt.validateResult != nil {
				tt.validateResult(t, configPath)
			}
		})
	}
}

func TestRunFunction(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		dryRun      bool
		expectError bool
	}{
		{
			name: "format without dry-run",
			config: `version: "alpha"
vendors:
  - id: "T"
    name: "Test"
    certificates:
      - name: "Cert"
        url: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "aa:bb:cc:dd"
`,
			dryRun:      false,
			expectError: false,
		},
		{
			name: "dry-run needs formatting",
			config: `version: alpha
vendors:
  - id: T
    name: Test
    certificates:
      - name: Cert
        url: https://example.com/cert.cer
        validation:
          fingerprint:
            sha1: aa:bb:cc:dd
`,
			dryRun:      true,
			expectError: true,
		},
		{
			name: "dry-run already formatted",
			config: `---
version: "alpha"
vendors:
    - id: "T"
      name: "Test"
      certificates:
        - name: "Cert"
          url: "https://example.com/cert.cer"
          validation:
            fingerprint:
                sha1: "AA:BB:CC:DD"
`,
			dryRun:      false,
			expectError: false,
		},
		{
			name:        "file does not exist",
			config:      "",
			dryRun:      false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			testConfigPath := filepath.Join(tmpDir, "test.yaml")

			if tt.config != "" {
				if err := os.WriteFile(testConfigPath, []byte(tt.config), 0644); err != nil {
					t.Fatalf("failed to write test config: %v", err)
				}
			} else {
				testConfigPath = filepath.Join(tmpDir, "nonexistent.yaml")
			}

			// Save original values
			origConfigPath := configPath
			origDryRun := dryRun

			// Set test values
			configPath = testConfigPath
			dryRun = tt.dryRun

			// Run the command
			err := run(nil, nil)

			// Restore original values
			configPath = origConfigPath
			dryRun = origDryRun

			// Check expectations
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
