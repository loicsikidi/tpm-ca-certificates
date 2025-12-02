package validate

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateCommand(t *testing.T) {
	tests := []struct {
		name           string
		configContent  string
		quiet          bool
		expectExit     bool
		expectOutput   bool
		outputContains string
	}{
		{
			name: "valid config without quiet",
			configContent: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates:
      - name: "Test Certificate"
        url: "https://example.com/cert.crt"
        validation:
          fingerprint:
            sha256: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
`,
			quiet:          false,
			expectExit:     false,
			expectOutput:   true,
			outputContains: "is valid",
		},
		{
			name: "valid config with quiet",
			configContent: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates:
      - name: "Test Certificate"
        url: "https://example.com/cert.crt"
        validation:
          fingerprint:
            sha256: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
`,
			quiet:        true,
			expectExit:   false,
			expectOutput: false,
		},
		{
			name: "invalid config without quiet",
			configContent: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "INVALID"
    certificates:
      - name: "Test Certificate"
        url: "http://example.com/cert.crt"
        validation:
          fingerprint:
            sha256: "invalid-fingerprint"
`,
			quiet:          false,
			expectExit:     true,
			expectOutput:   true,
			outputContains: "validation errors",
		},
		{
			name: "invalid config with quiet",
			configContent: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "INVALID"
    certificates:
      - name: "Test Certificate"
        url: "http://example.com/cert.crt"
        validation:
          fingerprint:
            sha256: "invalid-fingerprint"
`,
			quiet:        true,
			expectExit:   true,
			expectOutput: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpDir := t.TempDir()
			configPath = filepath.Join(tmpDir, ".tpm-roots.yaml")

			if err := os.WriteFile(configPath, []byte(tt.configContent), 0644); err != nil {
				t.Fatalf("failed to create test config: %v", err)
			}

			// Set quiet flag
			quiet = tt.quiet

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
			if tt.outputContains != "" && !contains(output, tt.outputContains) {
				t.Errorf("expected output to contain '%s', got: %s", tt.outputContains, output)
			}

			// Reset osExit
			osExit = os.Exit
		})
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || bytes.Contains([]byte(s), []byte(substr)))
}
