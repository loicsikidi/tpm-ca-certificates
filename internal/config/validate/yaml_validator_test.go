package validate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestYAMLValidator_ValidateFile(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		wantErrors  int
		errorChecks []string
	}{
		{
			name: "valid file",
			yaml: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates:
      - name: "Cert A"
        url: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors: 0,
		},
		{
			name: "unsorted vendors",
			yaml: `version: "alpha"
vendors:
  - name: "Nuvoton Technology"
    id: "NTC"
    certificates:
      - name: "Cert A"
        url: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
  - name: "Intel"
    id: "INTC"
    certificates:
      - name: "Cert A"
        url: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  2,
			errorChecks: []string{"vendors not sorted"},
		},
		{
			name: "unsorted certificates",
			yaml: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates:
      - name: "Cert Z"
        url: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
      - name: "Cert A"
        url: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  2,
			errorChecks: []string{"certificates not sorted"},
		},
		{
			name: "unencoded URL",
			yaml: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates:
      - name: "Cert A"
        url: "https://example.com/cert with space.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  1,
			errorChecks: []string{"URL not properly encoded"},
		},
		{
			name: "http URL",
			yaml: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates:
      - name: "Cert A"
        url: "http://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  1,
			errorChecks: []string{"URL must use HTTPS scheme"},
		},
		{
			name: "lowercase fingerprint",
			yaml: `version: "alpha"
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates:
      - name: "Cert A"
        url: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd"
`,
			wantErrors:  1,
			errorChecks: []string{"fingerprint not in uppercase"},
		},
		{
			name: "unquoted string",
			yaml: `version: alpha
vendors:
  - name: "STMicroelectronics"
    id: "STM"
    certificates:
      - name: "Cert A"
        url: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  1,
			errorChecks: []string{"not double-quoted"},
		},
		{
			name: "invalid vendor ID",
			yaml: `version: "alpha"
vendors:
  - name: "Unknown Vendor"
    id: "INVALID"
    certificates:
      - name: "Cert A"
        url: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  1,
			errorChecks: []string{"invalid vendor ID", "not found in TCG TPM Vendor ID Registry"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			testFile := filepath.Join(tmpDir, "test.yaml")

			if err := os.WriteFile(testFile, []byte(tt.yaml), 0644); err != nil {
				t.Fatal(err)
			}

			validator := NewYAMLValidator()
			errors, err := validator.ValidateFile(testFile)
			if err != nil {
				t.Fatalf("ValidateFile() unexpected error: %v", err)
			}

			if len(errors) != tt.wantErrors {
				t.Errorf("ValidateFile() got %d errors, want %d", len(errors), tt.wantErrors)
				for _, e := range errors {
					t.Logf("  Line %d: %s", e.Line, e.Message)
				}
			}

			for _, check := range tt.errorChecks {
				found := false
				for _, e := range errors {
					if contains(e.Message, check) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected error containing %q, but not found", check)
				}
			}
		})
	}
}

func TestIsValidFingerprintFormat(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid uppercase with colons",
			input: "AA:BB:CC:DD",
			want:  true,
		},
		{
			name:  "valid sha1",
			input: "7C:7B:3C:8A:46:5E:67:D2:8F:4D:B0:F3:5C:E1:20:C4:BB:4A:AC:CC",
			want:  true,
		},
		{
			name:  "lowercase",
			input: "aa:bb:cc:dd",
			want:  false,
		},
		{
			name:  "no colons",
			input: "AABBCCDD",
			want:  false,
		},
		{
			name:  "wrong colon placement",
			input: "AAA:BB:CC",
			want:  false,
		},
		{
			name:  "invalid hex",
			input: "GG:HH:II:JJ",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidFingerprintFormat(tt.input)
			if got != tt.want {
				t.Errorf("isValidFingerprintFormat(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
