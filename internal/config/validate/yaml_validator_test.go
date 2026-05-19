package validate_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config/validate"
	"github.com/loicsikidi/tpm-ca-certificates/internal/fingerprint"
)

func TestYAMLValidator_ValidateFile(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		wantErrors  int
		errorChecks []string
		wantError   string // if non-empty, expect ValidateFile() to return an error containing this string
	}{
		{
			name: "valid file",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors: 0,
		},
		{
			name: "missing YAML document marker",
			yaml: `version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  1,
			errorChecks: []string{"must start with YAML document marker"},
		},
		{
			name: "comment before document marker",
			yaml: `# This is a comment
---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates: []
`,
			wantErrors:  1,
			errorChecks: []string{"must start with YAML document marker"},
		},
		{
			name: "unsorted vendors",
			yaml: `---
version: "alpha"
vendors:
  - id: "NTC"
    name: "Nuvoton Technology"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
  - id: "INTC"
    name: "Intel"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  2,
			errorChecks: []string{"vendors not sorted"},
		},
		{
			name: "unsorted certificates",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert Z"
        uri: "https://example.com/cert-z.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
      - name: "Cert A"
        uri: "https://example.com/cert-a.cer"
        validation:
          fingerprint:
            sha1: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44"
`,
			wantErrors:  2,
			errorChecks: []string{"certificates not sorted"},
		},
		{
			name: "unencoded URL",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert with space.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  1,
			errorChecks: []string{"uri not properly encoded"},
		},
		{
			name: "http URL",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "http://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantError: "invalid uri scheme 'http'",
		},
		{
			name: "lowercase fingerprint",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd"
`,
			wantErrors:  1,
			errorChecks: []string{"fingerprint not in uppercase"},
		},
		{
			name: "unquoted string",
			yaml: `---
version: alpha
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  1,
			errorChecks: []string{"not double-quoted"},
		},
		{
			name: "invalid vendor ID",
			yaml: `---
version: "alpha"
vendors:
  - id: "INVALID"
    name: "Unknown Vendor"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  1,
			errorChecks: []string{"invalid vendor ID", "not found in TCG TPM Vendor ID Registry"},
		},
		{
			name: "duplicate vendor IDs",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert-a.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
  - id: "STM"
    name: "STMicroelectronics Duplicate"
    certificates:
      - name: "Cert B"
        uri: "https://example.com/cert-b.cer"
        validation:
          fingerprint:
            sha1: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44"
`,
			wantErrors:  1,
			errorChecks: []string{"duplicate vendor ID", "STM"},
		},
		{
			name: "duplicate certificate by name",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert-a.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
      - name: "Cert A"
        uri: "https://example.com/cert-b.cer"
        validation:
          fingerprint:
            sha1: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44"
`,
			wantErrors:  1,
			errorChecks: []string{"duplicate certificate", "Cert A"},
		},
		{
			name: "duplicate certificate by URL",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
      - name: "Cert B"
        uri: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44"
`,
			wantErrors:  1,
			errorChecks: []string{"duplicate certificate", "Cert B"},
		},
		{
			name: "duplicate certificate by fingerprint",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert-a.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
      - name: "Cert B"
        uri: "https://example.com/cert-b.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  1,
			errorChecks: []string{"duplicate certificate", "Cert B"},
		},
		{
			name: "valid URI with https scheme",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors: 0,
		},
		{
			name: "valid URI with file scheme",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "file:///{local}/certs/cert.der"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors: 0,
		},
		{
			name: "unencoded URI",
			yaml: `---
version: "alpha"
vendors:
  - id: "STM"
    name: "STMicroelectronics"
    certificates:
      - name: "Cert A"
        uri: "https://example.com/cert with space.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
`,
			wantErrors:  1,
			errorChecks: []string{"uri not properly encoded"},
		},
		{
			name: "unencoded URI reports correct line number",
			yaml: `---
version: "alpha"
vendors:
  - id: "AMD"
    name: "AMD"
    certificates:
      - name: "AMDTPM ECC"
        description: "test certificate"
        uri: "https://example.com/cert with space.der"
        validation:
          fingerprint:
            sha256: "C2:CB:57:BF:72:3C:17:4F:16:6C:5A:A1:DC:64:16:09:81:05:4B:EE:18:C7:0E:B1:DE:BF:C1:51:8A:FA:92:D2"
`,
			wantErrors:  1,
			errorChecks: []string{"uri not properly encoded"},
		},
		{
			name: "unencoded URL reports correct line number",
			yaml: `---
version: "alpha"
vendors:
  - id: "AMD"
    name: "AMD"
    certificates:
      - name: "AMDTPM ECC"
        description: "test certificate"
        uri: "https://example.com/cert with space.der"
        validation:
          fingerprint:
            sha256: "C2:CB:57:BF:72:3C:17:4F:16:6C:5A:A1:DC:64:16:09:81:05:4B:EE:18:C7:0E:B1:DE:BF:C1:51:8A:FA:92:D2"
`,
			wantErrors:  1,
			errorChecks: []string{"uri not properly encoded"},
		},
		{
			name: "multiple unencoded URIs report correct line numbers",
			yaml: `---
version: "alpha"
vendors:
  - id: "AMD"
    name: "AMD"
    certificates:
      - name: "Cert A"
        uri: "https://valid.com/cert.der"
        validation:
          fingerprint:
            sha256: "C2:CB:57:BF:72:3C:17:4F:16:6C:5A:A1:DC:64:16:09:81:05:4B:EE:18:C7:0E:B1:DE:BF:C1:51:8A:FA:92:D2"
      - name: "Cert B"
        description: "note: unencoded URI"
        uri: "https://example.com/cert with space.der"
        validation:
          fingerprint:
            sha256: "B7:3F:14:DE:A3:BD:AA:0B:E8:74:40:DE:3F:C7:18:C7:71:F2:CB:F8:B7:B2:23:1C:6E:A2:28:D3:B2:08:60:EF"
`,
			wantErrors:  1,
			errorChecks: []string{"uri not properly encoded"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			testFile := filepath.Join(tmpDir, "test.yaml")

			if err := os.WriteFile(testFile, []byte(tt.yaml), 0644); err != nil {
				t.Fatal(err)
			}

			validator := validate.NewYAMLValidator()
			errors, err := validator.ValidateFile(testFile)

			if tt.wantError != "" {
				if err == nil {
					t.Fatalf("ValidateFile() expected error containing %q, but got nil", tt.wantError)
				}
				if !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("ValidateFile() error = %q, want error containing %q", err.Error(), tt.wantError)
				}
				return
			}
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
					if strings.Contains(e.Message, check) {
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
			got := fingerprint.IsValid(tt.input)
			if got != tt.want {
				t.Errorf("fingerprint.IsValid(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
