package format

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/loicsikidi/tpm-ca-certificates/internal/config"
)

func TestFormatFingerprint(t *testing.T) {
	f := NewFormatter()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "lowercase with colons",
			input: "aa:bb:cc:dd",
			want:  "AA:BB:CC:DD",
		},
		{
			name:  "lowercase without colons",
			input: "aabbccdd",
			want:  "AA:BB:CC:DD",
		},
		{
			name:  "mixed case with colons",
			input: "Aa:bB:Cc:Dd",
			want:  "AA:BB:CC:DD",
		},
		{
			name:  "already formatted",
			input: "AA:BB:CC:DD",
			want:  "AA:BB:CC:DD",
		},
		{
			name:  "with spaces",
			input: "AA BB CC DD",
			want:  "AA:BB:CC:DD",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "sha1 fingerprint",
			input: "7c:7b:3c:8a:46:5e:67:d2:8f:4d:b0:f3:5c:e1:20:c4:bb:4a:ac:cc",
			want:  "7C:7B:3C:8A:46:5E:67:D2:8F:4D:B0:F3:5C:E1:20:C4:BB:4A:AC:CC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.formatFingerprint(tt.input)
			if got != tt.want {
				t.Errorf("formatFingerprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEncodeURL(t *testing.T) {
	f := NewFormatter()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "url with unencoded space",
			input: "https://example.com/Nuvoton TPM Root CA.cer",
			want:  "https://example.com/Nuvoton%20TPM%20Root%20CA.cer",
		},
		{
			name:  "url already encoded",
			input: "https://example.com/Nuvoton%20TPM%20Root%20CA.cer",
			want:  "https://example.com/Nuvoton%20TPM%20Root%20CA.cer",
		},
		{
			name:  "url without spaces",
			input: "https://example.com/cert.cer",
			want:  "https://example.com/cert.cer",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.encodeURL(tt.input)
			if got != tt.want {
				t.Errorf("encodeURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyFormatting(t *testing.T) {
	f := NewFormatter()

	cfg := &config.TPMRootsConfig{
		Version: "alpha",
		Vendors: []config.Vendor{
			{
				Name: "Vendor B",
				ID:   "VB",
				Certificates: []config.Certificate{
					{
						Name: "Cert Z",
						URL:  "https://example.com/z.cer",
						Validation: config.Validation{
							Fingerprint: config.Fingerprint{
								SHA1: "aa:bb:cc",
							},
						},
					},
					{
						Name: "Cert A",
						URL:  "https://example.com/a.cer",
						Validation: config.Validation{
							Fingerprint: config.Fingerprint{
								SHA1: "dd:ee:ff",
							},
						},
					},
				},
			},
			{
				Name: "Vendor A",
				ID:   "VA",
				Certificates: []config.Certificate{
					{
						Name: "Cert X",
						URL:  "https://example.com/x.cer",
						Validation: config.Validation{
							Fingerprint: config.Fingerprint{
								SHA1: "11:22:33",
							},
						},
					},
				},
			},
		},
	}

	f.applyFormatting(cfg)

	// Check vendors are sorted by ID
	if cfg.Vendors[0].ID != "VA" {
		t.Errorf("First vendor ID = %v, want VA", cfg.Vendors[0].ID)
	}
	if cfg.Vendors[1].ID != "VB" {
		t.Errorf("Second vendor ID = %v, want VB", cfg.Vendors[1].ID)
	}

	// Check certificates are sorted by name within vendor
	if cfg.Vendors[1].Certificates[0].Name != "Cert A" {
		t.Errorf("First cert name = %v, want Cert A", cfg.Vendors[1].Certificates[0].Name)
	}
	if cfg.Vendors[1].Certificates[1].Name != "Cert Z" {
		t.Errorf("Second cert name = %v, want Cert Z", cfg.Vendors[1].Certificates[1].Name)
	}

	// Check fingerprints are formatted
	if cfg.Vendors[1].Certificates[0].Validation.Fingerprint.SHA1 != "DD:EE:FF" {
		t.Errorf("Fingerprint = %v, want DD:EE:FF", cfg.Vendors[1].Certificates[0].Validation.Fingerprint.SHA1)
	}
}

func TestFormatFile(t *testing.T) {
	f := NewFormatter()

	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "test.yaml")
	outputPath := filepath.Join(tmpDir, "output.yaml")

	inputYAML := `version: alpha
vendors:
- id: TV
  name: Test Vendor
  certificates:
    - name: Test Cert
      url: https://example.com/test cert.cer
      validation:
        fingerprint:
          sha1: aa:bb:cc:dd
`

	if err := os.WriteFile(inputPath, []byte(inputYAML), 0644); err != nil {
		t.Fatal(err)
	}

	if err := f.FormatFile(inputPath, outputPath); err != nil {
		t.Fatalf("FormatFile() error = %v", err)
	}

	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}

	outputStr := string(output)

	// Check that file starts with ---
	if !strings.HasPrefix(outputStr, "---\n") {
		t.Error("Output should start with YAML document marker '---'")
	}

	// Check that strings are quoted
	if !strings.Contains(outputStr, `"alpha"`) {
		t.Error("Output should contain quoted version")
	}

	// Check that fingerprint is uppercase
	if !strings.Contains(outputStr, "AA:BB:CC:DD") {
		t.Error("Output should contain uppercase fingerprint")
	}

	// Check that URL is encoded
	if !strings.Contains(outputStr, "test%20cert.cer") {
		t.Error("Output should contain URL-encoded space")
	}
}

func TestEnsureYAMLDocumentMarker(t *testing.T) {
	f := NewFormatter()

	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "missing document marker",
			input: []byte("version: \"alpha\"\nvendors: []"),
			want:  "---\nversion: \"alpha\"\nvendors: []",
		},
		{
			name:  "already has document marker",
			input: []byte("---\nversion: \"alpha\"\nvendors: []"),
			want:  "---\nversion: \"alpha\"\nvendors: []",
		},
		{
			name:  "document marker with extra spaces should add correct marker",
			input: []byte("  ---  \nversion: \"alpha\""),
			want:  "---\n  ---  \nversion: \"alpha\"",
		},
		{
			name:  "empty file",
			input: []byte(""),
			want:  "---\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := f.ensureYAMLDocumentMarker(tt.input)
			if string(got) != tt.want {
				t.Errorf("ensureYAMLDocumentMarker() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestNeedsFormatting(t *testing.T) {
	f := NewFormatter()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name: "already formatted",
			input: `---
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
			want: false,
		},
		{
			name: "missing document marker",
			input: `version: "alpha"
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
			want: true,
		},
		{
			name: "needs formatting - no quotes",
			input: `---
version: alpha
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
			want: true,
		},
		{
			name: "needs formatting - lowercase fingerprint",
			input: `---
version: "alpha"
vendors:
  - id: "TV"
    name: "Test Vendor"
    certificates:
      - name: "Test Cert"
        url: "https://example.com/test.cer"
        validation:
          fingerprint:
            sha1: "aa:bb:cc:dd"
`,
			want: true,
		},
		{
			name: "needs formatting - unsorted vendors",
			input: `---
version: "alpha"
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
			want: true,
		},
		{
			name: "needs formatting - unsorted certificates",
			input: `---
version: "alpha"
vendors:
  - id: "TV"
    name: "Test Vendor"
    certificates:
      - name: "Z Cert"
        url: "https://example.com/z.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD"
      - name: "A Cert"
        url: "https://example.com/a.cer"
        validation:
          fingerprint:
            sha1: "AA:BB:CC:DD"
`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			inputPath := filepath.Join(tmpDir, "test.yaml")

			if err := os.WriteFile(inputPath, []byte(tt.input), 0644); err != nil {
				t.Fatal(err)
			}

			got, err := f.NeedsFormatting(inputPath)
			if err != nil {
				t.Fatalf("NeedsFormatting() error = %v", err)
			}

			if got != tt.want {
				t.Errorf("NeedsFormatting() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNeedsFormattingInvalidFile(t *testing.T) {
	f := NewFormatter()

	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		{
			name:      "file does not exist",
			input:     "/nonexistent/file.yaml",
			wantError: true,
		},
		{
			name:      "invalid yaml",
			input:     "invalid: yaml: content:",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var inputPath string
			if tt.name == "file does not exist" {
				inputPath = tt.input
			} else {
				tmpDir := t.TempDir()
				inputPath = filepath.Join(tmpDir, "test.yaml")
				if err := os.WriteFile(inputPath, []byte(tt.input), 0644); err != nil {
					t.Fatal(err)
				}
			}

			_, err := f.NeedsFormatting(inputPath)
			if (err != nil) != tt.wantError {
				t.Errorf("NeedsFormatting() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}
