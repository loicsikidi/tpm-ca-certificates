package vendors

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListCommand(t *testing.T) {
	tests := []struct {
		name           string
		config         string
		opts           listOptions
		expectError    bool
		expectedOutput []string
	}{
		{
			name: "list all vendors in table format",
			config: `version: "alpha"
vendors:
  - id: "VDA"
    name: "Vendor A"
    certificates:
      - name: "Cert A1"
        url: "https://example.com/a1.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
      - name: "Cert A2"
        url: "https://example.com/a2.crt"
        validation:
          fingerprint:
            sha256: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
  - id: "VDB"
    name: "Vendor B"
    certificates:
      - name: "Cert B1"
        url: "https://example.com/b1.crt"
        validation:
          fingerprint:
            sha1: "FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC"
`,
			opts:        listOptions{short: false},
			expectError: false,
			expectedOutput: []string{
				"VENDOR ID",
				"VENDOR NAME",
				"CERTIFICATES",
				"VDA",
				"Vendor A",
				"2",
				"VDB",
				"Vendor B",
				"1",
			},
		},
		{
			name: "list all vendors in short format",
			config: `version: "alpha"
vendors:
  - id: "VDA"
    name: "Vendor A"
    certificates:
      - name: "Cert A1"
        url: "https://example.com/a1.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
  - id: "VDB"
    name: "Vendor B"
    certificates:
      - name: "Cert B1"
        url: "https://example.com/b1.crt"
        validation:
          fingerprint:
            sha1: "FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC"
`,
			opts:        listOptions{short: true},
			expectError: false,
			expectedOutput: []string{
				"Vendor A (VDA)",
				"Vendor B (VDB)",
			},
		},
		{
			name: "no vendors found",
			config: `version: "alpha"
vendors: []
`,
			opts:           listOptions{},
			expectError:    true, // Will fail validation because at least one vendor is required
			expectedOutput: []string{},
		},
		{
			name: "single vendor with multiple certificates",
			config: `version: "alpha"
vendors:
  - id: "TST"
    name: "Test Vendor Corp"
    certificates:
      - name: "Cert 1"
        url: "https://example.com/1.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
      - name: "Cert 2"
        url: "https://example.com/2.crt"
        validation:
          fingerprint:
            sha1: "BB:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
      - name: "Cert 3"
        url: "https://example.com/3.crt"
        validation:
          fingerprint:
            sha1: "CC:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts:        listOptions{short: false},
			expectError: false,
			expectedOutput: []string{
				"TST",
				"Test Vendor Corp",
				"3",
			},
		},
		{
			name: "multiple vendors short format",
			config: `version: "alpha"
vendors:
  - id: "ALPHA"
    name: "Alpha Vendor"
    certificates:
      - name: "Cert"
        url: "https://example.com/cert.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
  - id: "BETA"
    name: "Beta Vendor"
    certificates:
      - name: "Cert"
        url: "https://example.com/cert.crt"
        validation:
          fingerprint:
            sha1: "BB:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
  - id: "GAMMA"
    name: "Gamma Vendor"
    certificates:
      - name: "Cert"
        url: "https://example.com/cert.crt"
        validation:
          fingerprint:
            sha1: "CC:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			opts:        listOptions{short: true},
			expectError: false,
			expectedOutput: []string{
				"Alpha Vendor (ALPHA)",
				"Beta Vendor (BETA)",
				"Gamma Vendor (GAMMA)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, ".tpm-roots.yaml")

			if err := os.WriteFile(configPath, []byte(tt.config), 0644); err != nil {
				t.Fatalf("failed to create test config: %v", err)
			}

			// Set config path
			tt.opts.configPath = configPath

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Run the list command
			err := runList(&tt.opts)

			// Restore stdout
			w.Close()
			os.Stdout = oldStdout

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Check error expectation
			if tt.expectError && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Validate output if no error expected
			if !tt.expectError {
				for _, expected := range tt.expectedOutput {
					if !strings.Contains(output, expected) {
						t.Errorf("expected output to contain '%s', but it didn't.\nFull output:\n%s", expected, output)
					}
				}
			}
		})
	}
}
