package certificates

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
			name: "list all certificates",
			config: `version: "alpha"
vendors:
  - name: "Vendor A"
    id: "VDA"
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
  - name: "Vendor B"
    id: "VDB"
    certificates:
      - name: "Cert B1"
        url: "https://example.com/b1.crt"
        validation:
          fingerprint:
            sha1: "FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC"
`,
			opts:        listOptions{},
			expectError: false,
			expectedOutput: []string{
				"Vendor: Vendor A (ID: VDA)",
				"Certificate: Cert A1",
				"URL: https://example.com/a1.crt",
				"SHA1:",
				"Certificate: Cert A2",
				"SHA256:",
				"Vendor: Vendor B (ID: VDB)",
				"Certificate: Cert B1",
			},
		},
		{
			name: "list certificates for specific vendor",
			config: `version: "alpha"
vendors:
  - name: "Vendor A"
    id: "VDA"
    certificates:
      - name: "Cert A1"
        url: "https://example.com/a1.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
  - name: "Vendor B"
    id: "VDB"
    certificates:
      - name: "Cert B1"
        url: "https://example.com/b1.crt"
        validation:
          fingerprint:
            sha1: "FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:FF:EE:DD:CC"
`,
			opts: listOptions{
				vendorID: "VDA",
			},
			expectError: false,
			expectedOutput: []string{
				"Vendor: Vendor A (ID: VDA)",
				"Certificate: Cert A1",
			},
		},
		{
			name: "error when vendor not found",
			config: `version: "alpha"
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
			opts: listOptions{
				vendorID: "NONEXISTENT",
			},
			expectError: true,
		},
		{
			name: "list certificate with multiple fingerprints",
			config: `version: "alpha"
vendors:
  - name: "Test Vendor"
    id: "TST"
    certificates:
      - name: "Multi-Hash Cert"
        url: "https://example.com/multi.crt"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
            sha256: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
            sha512: "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00"
`,
			opts:        listOptions{},
			expectError: false,
			expectedOutput: []string{
				"Certificate: Multi-Hash Cert",
				"SHA1:",
				"SHA256:",
				"SHA512:",
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
