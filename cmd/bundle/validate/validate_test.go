package validate

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/testutil"
)

func TestValidateCommand(t *testing.T) {
	tests := []struct {
		name          string
		getBundleData func() ([]byte, error)
		quiet         bool
		wantExitCode  int
		wantOutput    bool
		wantError     bool
	}{
		{
			name: "valid bundle without quiet",
			getBundleData: func() ([]byte, error) {
				return testutil.ReadTestFile(testutil.BundleFile)
			},
			quiet:        false,
			wantExitCode: 0,
			wantOutput:   true,
		},
		{
			name: "valid bundle with quiet",
			getBundleData: func() ([]byte, error) {
				return testutil.ReadTestFile(testutil.BundleFile)
			},
			quiet:        true,
			wantExitCode: 0,
			wantOutput:   false,
		},
		{
			name: "invalid bundle without quiet",
			getBundleData: func() ([]byte, error) {
				return []byte(`# Certificate: Test
# Owner: STM
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHCgVZU2T9MA0GCSqGSIb3DQEBCwUAMA0xCzAJBgNVBAYTAlVT
-----END CERTIFICATE-----`), nil
			},
			quiet:        false,
			wantExitCode: 1,
			wantOutput:   true,
		},
		{
			name: "invalid bundle with quiet",
			getBundleData: func() ([]byte, error) {
				return []byte(`# Certificate: Test
-----BEGIN CERTIFICATE-----
INVALID
-----END CERTIFICATE-----`), nil
			},
			quiet:        true,
			wantExitCode: 1,
			wantOutput:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory
			tmpDir := t.TempDir()

			// Write test bundle
			bundleData, err := tt.getBundleData()
			if err != nil {
				t.Fatalf("failed to get test bundle data: %v", err)
			}

			bundlePath = filepath.Join(tmpDir, "bundle.pem")
			if err := os.WriteFile(bundlePath, bundleData, 0644); err != nil {
				t.Fatalf("failed to write test bundle: %v", err)
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

			// Track os.Exit calls
			exitCalled := false
			exitCode := -1
			osExit = func(code int) {
				exitCalled = true
				exitCode = code
			}

			// Run the command
			err = run(nil, []string{bundlePath})

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

			// Reset osExit
			osExit = os.Exit

			// Check results
			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tt.wantExitCode > 0 && !exitCalled {
				t.Errorf("expected os.Exit to be called with code %d", tt.wantExitCode)
			}

			if tt.wantExitCode == 0 && exitCalled {
				t.Errorf("os.Exit(%d) called, but expected success", exitCode)
			}

			if exitCalled && exitCode != tt.wantExitCode {
				t.Errorf("expected exit code %d, got %d", tt.wantExitCode, exitCode)
			}

			if !tt.wantOutput {
				if output != "" {
					t.Errorf("expected no output in quiet mode, got: %s", output)
				}
			} else {
				if output == "" {
					t.Error("expected output but got none")
				}
			}
		})
	}
}

func TestValidateCommand_FileNotFound(t *testing.T) {
	bundlePath = "/nonexistent/bundle.pem"
	quiet = false

	err := run(nil, []string{bundlePath})
	if err == nil {
		t.Error("expected error for nonexistent file")
	}

	if !contains(err.Error(), "failed to read bundle") {
		t.Errorf("expected 'failed to read bundle' error, got: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || bytes.Contains([]byte(s), []byte(substr)))
}
